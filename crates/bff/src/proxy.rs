//! Forwards `/api/*` to the API with the session's access token.
//!
//! # Backend for frontend (BFF)
//!
//! This is the "backend for frontend" pattern recommended for browser apps by the IETF's
//! *OAuth 2.0 for Browser-Based Applications*. The browser never holds a token. It only has
//! an `HttpOnly` session cookie, which page scripts cannot read; the access and refresh tokens
//! stay on the server, in Redis. When the SPA calls the API, it calls the BFF on its own
//! origin instead, and the BFF makes the call on its behalf:
//!
//! ```text
//! browser ──(session cookie + x-bff-csrf)──▶ BFF ──(Authorization: Bearer <token>)──▶ API
//! ```
//!
//! For each `/api/*` request the BFF:
//!
//! 1. finds the session from the cookie (no session: 401);
//! 2. gets an access token valid for at least another minute, refreshing it at the identity
//!    provider if needed (see [`crate::session`]);
//! 3. builds the API URL from `API_BASE_URL` and the path after `/api`, refusing paths that
//!    could leave that base (see `api_url`);
//! 4. removes the browser's credentials and the headers meant for its connection or claiming
//!    who it is, adds the bearer token and its own `X-Forwarded-For`;
//! 5. streams the request to the API and the API's answer back, minus any cookies the API
//!    tries to set.
//!
//! # Design rationale
//!
//! - **Tokens cannot be stolen from the browser.** A script injected into the SPA (XSS) can
//!   still make requests while the user is on the page, but it cannot read a token and take
//!   it elsewhere, since there is none in the browser.
//! - **The API stays an ordinary bearer-token API.** It verifies the access token like any
//!   OAuth 2.0 resource server and knows nothing about cookies or the BFF.
//! - **One origin for the SPA.** The SPA is served from the same origin as the BFF, so its
//!   sign-in and API calls are same-origin: there is no CORS to configure, and the session
//!   cookie can be `SameSite=Strict`.
//! - **Cross-site requests are refused.** State-changing calls need the `x-bff-csrf` header,
//!   which another site cannot add without a CORS preflight the BFF never grants
//!   (see [`crate::csrf`]).
//!
//! The proxy makes no authorization decisions: it only proves who the user is, through the
//! token. What the user may do is for the API to decide from that token.

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Uri,
        header::{AUTHORIZATION, CONNECTION, COOKIE, HOST, SET_COOKIE},
    },
    response::Response,
    routing::any,
};
use reqwest::Url;

use std::net::SocketAddr;

use axum::extract::ConnectInfo;

use crate::{
    csrf::CSRF_HEADER,
    error::AppError,
    session::{CurrentSession, refresh_access_token},
    state::AppState,
};

/// Headers about a single connection ("hop"), not about the request itself (RFC 9110 §7.6.1).
///
/// A proxied request travels over two separate connections: browser → BFF, then BFF → API
/// (and the answer back the same way). These headers describe only the connection they
/// arrived on, so passing them to the next one would make the API act on settings never meant
/// for it:
///
/// - `transfer-encoding` says how this connection's body is cut into pieces. The BFF sends the
///   body on with its own framing, so a forwarded value would no longer match the bytes. Two
///   servers disagreeing on where a request ends is how "request smuggling" works: the API
///   would read a second, hidden request inside the body, one the BFF never checked.
/// - `upgrade` asks to switch the connection to another protocol, e.g. WebSocket; the BFF
///   only forwards ordinary HTTP requests.
/// - `proxy-authorization` and `proxy-authenticate` carry credentials for a proxy along the
///   way, not for the API.
/// - `keep-alive`, `proxy-connection`, `te` and `trailer` tune connection reuse and body
///   encodings for this connection only.
///
/// Nothing is lost by dropping them: the HTTP libraries on each side set what their own
/// connection needs.
const HOP_BY_HOP: [&str; 8] = [
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// `/api/{*rest}`: every method, forwarded to the API.
pub fn routes() -> Router<AppState> {
    Router::new().route("/api/{*rest}", any(api))
}

/// Headers in which a proxy in front reports who the client is and how it connected: its IP
/// address (`forwarded`, `x-forwarded-for`, `x-real-ip`, `cf-connecting-ip`,
/// `true-client-ip`), the host name, port and path prefix it asked for (`x-forwarded-host`,
/// `x-forwarded-port`, `x-forwarded-prefix`), whether it used HTTPS (`x-forwarded-proto`), and
/// which proxy handled it (`x-forwarded-server`). An ingress such as Traefik adds most of these
/// to every request it forwards.
///
/// They are ordinary text, and a browser or script can send them too. An API that trusts
/// them, to log who called, rate-limit per address, allow an office network, or build links,
/// could be told anything: `x-forwarded-for: 10.0.0.1` to pass as an internal caller, or
/// another address on every request to dodge a per-address limit. So the BFF removes all of
/// them, and the API gets a single `x-forwarded-for` set by the BFF itself, holding the
/// address it determined: the connection's, or a trusted proxy's header (see
/// [`crate::client_ip::ClientIpSource`]).
const FORWARDING: [&str; 10] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-prefix",
    "x-forwarded-proto",
    "x-forwarded-server",
    "x-real-ip",
    "cf-connecting-ip",
    "true-client-ip",
];

/// Forwards `request` to the API as `{API_BASE_URL}/{rest}`, with the session's access token
/// (refreshed if needed) instead of the browser's credentials, and streams the answer back.
/// `app_state` has the API client and settings, `peer` is the connection's address (for
/// `X-Forwarded-For`), and `current_session` is the signed-in session.
async fn api(
    State(app_state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    current_session: CurrentSession,
    request: Request,
) -> Result<Response, AppError> {
    let api_base_url = app_state.api_base_url.clone().ok_or(AppError::NoApiUrl)?;
    let token = refresh_access_token(&app_state, current_session)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let (parts, body) = request.into_parts();
    let url = api_url(&api_base_url, &parts.uri).ok_or(AppError::InvalidApiPath)?;

    let mut headers = parts.headers;
    strip_hop_by_hop(&mut headers);
    // The browser's credentials stay at the BFF: its cookies hold the BFF session, and any
    // `Authorization` it sends is replaced by the session's token below. `Host` names the
    // BFF; the HTTP client sets the API's own.
    for name in [AUTHORIZATION, COOKIE, HOST] {
        headers.remove(name);
    }
    // Only meaningful between the SPA and the BFF.
    headers.remove(CSRF_HEADER);
    // Read before the forwarding headers go: a trusted proxy's header may hold the client.
    let client = app_state.client_ip.client_ip(&headers, peer);
    strip_forwarding(&mut headers);
    headers.insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&client.to_string())?,
    );
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );

    let api_response = app_state
        .api_http
        .request(parts.method, url)
        .headers(headers)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await
        .map_err(|e| AppError::ProxyRequestFailed(e.to_string()))?;
    let mut response_headers = api_response.headers().clone();
    let mut response = Response::builder().status(api_response.status());
    strip_hop_by_hop(&mut response_headers);
    // A cookie the API set would land on the BFF's origin and be sent with every later
    // request there, outside the BFF's control.
    response_headers.remove(SET_COOKIE);

    if let Some(headers) = response.headers_mut() {
        headers.extend(response_headers);
    }

    Ok(response.body(Body::from_stream(api_response.bytes_stream()))?)
}

/// The API URL for browser request `uri`: its path after `/api`, with its query, appended to
/// `api_base_url`. `None` if the path has `.` or `..` segments (also percent-encoded or split by
/// backslashes), which URL parsing or the API might resolve to a path outside the base, or if
/// the result is not under it.
fn api_url(api_base_url: &str, uri: &Uri) -> Option<Url> {
    let path = uri.path().strip_prefix("/api").unwrap_or(uri.path());
    // Decoded the way lenient servers might: `%2e` as `.`, `\` and `%5c` as `/`.
    let decoded = path
        .to_ascii_lowercase()
        .replace("%2e", ".")
        .replace("%5c", "/")
        .replace('\\', "/");
    let has_dot_segment = decoded
        .split('/')
        .any(|segment| segment == "." || segment == "..");
    if has_dot_segment {
        return None;
    }
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let base = api_base_url.trim_end_matches('/');
    let url = Url::parse(&format!("{base}{path}{query}")).ok()?;
    url.as_str().starts_with(base).then_some(url)
}

/// Removes from `headers` every header in which a client or a proxy claims who the client is or
/// how it connected ([`FORWARDING`]); the BFF then adds its own `x-forwarded-for`.
fn strip_forwarding(headers: &mut HeaderMap) {
    for name in FORWARDING {
        headers.remove(name);
    }
}

/// Removes from `headers` the hop-by-hop headers ([`HOP_BY_HOP`]). Applied to the browser's
/// request before it goes to the API, and to the API's response before it goes back. A sender
/// can also declare its own connection-only headers by listing them in `Connection` (e.g.
/// `Connection: x-trace-hop`); those are removed too, then `Connection` itself.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();

    for name in listed {
        headers.remove(name);
    }

    headers.remove(CONNECTION);

    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, Uri};

    use crate::proxy::{api_url, strip_forwarding};

    const BASE: &str = "http://api.internal/v1";

    fn target(path_and_query: &str) -> Option<String> {
        let uri: Uri = path_and_query.parse().unwrap();
        api_url(BASE, &uri).map(String::from)
    }

    #[test]
    fn given_an_api_path_then_it_maps_under_the_base_with_its_query() {
        assert_eq!(
            target("/api/orders/7?page=2").as_deref(),
            Some("http://api.internal/v1/orders/7?page=2")
        );
    }

    #[test]
    fn given_dot_segments_then_the_path_is_refused() {
        for path in [
            "/api/../admin",
            "/api/%2e%2e/admin",
            "/api/%2E%2E/%2e%2e/metrics",
            "/api/orders/./7",
            "/api/orders/%2e/7",
            "/api/..%5Cadmin",
        ] {
            assert_eq!(target(path), None, "{path}");
        }
    }

    #[test]
    fn given_dots_inside_a_segment_then_the_path_is_kept() {
        assert_eq!(
            target("/api/files/report..final.pdf").as_deref(),
            Some("http://api.internal/v1/files/report..final.pdf")
        );
    }

    #[test]
    fn given_the_headers_an_ingress_adds_then_none_of_them_reach_the_api() {
        // What Traefik sets on every request it forwards, plus the other proxies' variants; a
        // browser can send any of them too.
        let claimed = [
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-port",
            "x-forwarded-prefix",
            "x-forwarded-proto",
            "x-forwarded-server",
            "x-real-ip",
            "forwarded",
            "cf-connecting-ip",
            "true-client-ip",
        ];
        let mut headers = HeaderMap::new();
        for name in claimed {
            headers.insert(name, HeaderValue::from_static("forged"));
        }
        headers.insert("accept", HeaderValue::from_static("application/json"));

        strip_forwarding(&mut headers);

        for name in claimed {
            assert!(!headers.contains_key(name), "{name} reached the API");
        }
        assert_eq!(
            headers["accept"], "application/json",
            "ordinary headers stay"
        );
    }
}
