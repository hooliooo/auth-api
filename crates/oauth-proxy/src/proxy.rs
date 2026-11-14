//! The proxy's routes: `/api/*` answered here with the session's access token, everything else
//! passed to the OAuth agent unchanged.
//!
//! For `/api/*`, in order: the request gets an id; it must carry the CSRF header (403) and a
//! session cookie whose session opens (401); its access token must be valid for another minute, or
//! the OAuth agent's internal endpoint must give a fresh one (401 if the session ended, 502 or 503
//! if the OAuth agent or the identity provider cannot); the API must be configured (503) and the
//! path must stay under its base (400). The request then goes to the API with the token instead of
//! the browser's credentials ([`to_api`]), and the API's answer comes back without its cookies
//! ([`from_api`]), both streamed.
//!
//! Everything else (sign-in, the callback, logout, the session, health, the public key set) goes to
//! the OAuth agent with only the connection-only headers removed: cookies, `Host` and redirects
//! pass untouched both ways, and the OAuth agent applies its own CSRF check, request ids and
//! metrics.
//!
//! # Design rationale
//!
//! This is the token handler pattern: the Backend for Frontend (BFF) of RFC 10017 (*OAuth 2.0
//! for Browser-Based Applications*, §6.1), split into an OAuth agent and this OAuth proxy.
//! Together they are the RFC's BFF: the agent is its confidential client and session manager,
//! the proxy its request forwarder. Like the RFC's BFF, the proxy is an application-layer reverse
//! proxy, not a forward HTTP proxy, and is bound by its proxy restrictions (§6.1.3.6): one
//! configured API, and no path that could leave its base.
//!
//! - **Tokens cannot be stolen from the browser.** The browser only has an `HttpOnly` session
//!   cookie. A script injected into the SPA (XSS) can still make requests while the user is on
//!   the page, but it cannot read a token and take it elsewhere, since there is none there.
//! - **The API stays an ordinary bearer-token API.** It verifies the access token like any
//!   OAuth 2.0 resource server and knows nothing about cookies or the proxy.
//! - **One origin for the SPA.** Its sign-in and API calls are same-origin: there is no CORS to
//!   configure, and the session cookie can be `SameSite=Strict`.
//! - **Cross-site requests are refused.** Every call, reads included, needs the CSRF header,
//!   which another origin cannot add without a CORS preflight that is never granted.
//! - **Only the OAuth agent holds credentials.** This hot path reads sessions and never talks to
//!   the identity provider; refreshes go through the OAuth agent.
//!
//! The proxy makes no authorization decisions: it only proves who the user is, through the
//! token. What the user may do is for the API to decide from that token.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CONNECTION, COOKIE, HOST, InvalidHeaderValue, SET_COOKIE},
    },
    middleware,
    response::{IntoResponse, Response},
    routing::any,
};
use reqwest::{Url, redirect};
use token_handler_common::{
    causes::with_causes,
    cookie,
    csrf::{self, CSRF_HEADER, PathRule},
    metrics, request_id,
};
use tracing::{debug, warn};

use crate::{
    config::{CONNECT_TIMEOUT, Config, READ_TIMEOUT},
    tokens::Tokens,
};

/// `/api/*`, counted under this route template, as the OAuth agent counted it.
const API_ROUTE: &str = "/api/{*rest}";

/// What every request handler shares. Cheap to clone.
#[derive(Clone)]
pub struct ProxyState {
    /// The settings.
    config: Arc<Config>,
    /// Session cookies to access tokens.
    tokens: Tokens,
    /// For the API and the OAuth agent: never follows a redirect, never decompresses a body, so
    /// both reach the browser as they were sent.
    upstream: reqwest::Client,
}

impl ProxyState {
    /// The state for `config`.
    pub fn new(config: Config) -> reqwest::Result<Self> {
        let tokens = Tokens::new(
            &config.redis_uri,
            &config.agent_internal_url,
            &config.internal_secret,
            CONNECT_TIMEOUT,
        )?;
        let upstream = reqwest::Client::builder()
            .redirect(redirect::Policy::none())
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .build()?;
        Ok(Self {
            config: Arc::new(config),
            tokens,
            upstream,
        })
    }
}

/// The proxy's routes on `state`.
pub fn router(state: ProxyState) -> Router {
    let api = Router::new()
        .route(API_ROUTE, any(api))
        .layer(middleware::from_fn_with_state(
            always as PathRule,
            csrf::require_header,
        ))
        // Outside the CSRF check, so refused requests are counted too.
        .layer(middleware::from_fn(metrics::track))
        // Outermost, so even refused requests get an id.
        .layer(middleware::from_fn(request_id::middleware));
    Router::new()
        .merge(api)
        .fallback(to_agent)
        .with_state(state)
}

/// The proxy's CSRF rule: every `/api/*` call acts on the session.
fn always(_path: &str) -> bool {
    true
}

/// `/api/*`: forwards `request` to the API with the session's access token, from client
/// connection `peer`; a refusal is an empty response with its status.
async fn api(
    State(state): State<ProxyState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let path = request.uri().path().to_owned();
    match forward_to_api(&state, peer, request).await {
        Ok(response) => response,
        Err(status) => {
            debug!(%status, %path, "API call refused");
            status.into_response()
        }
    }
}

/// Checks `request` and forwards it to the API; the status to refuse it with otherwise.
async fn forward_to_api(
    state: &ProxyState,
    peer: SocketAddr,
    request: Request,
) -> Result<Response, StatusCode> {
    let sid = cookie::get(request.headers(), cookie::SESSION).ok_or(StatusCode::UNAUTHORIZED)?;
    let token = state
        .tokens
        .access_token(&sid)
        .await?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let base = state
        .config
        .api_base_url
        .as_deref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let (parts, body) = request.into_parts();
    let url = api_url(base, parts.uri.path(), parts.uri.query()).ok_or(StatusCode::BAD_REQUEST)?;
    // Read before the forwarding headers go: a trusted proxy's header may hold the client.
    let client = state.config.client_ip.client_ip(&parts.headers, peer);
    let mut headers = parts.headers;
    to_api(&mut headers, client, &token).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let response = state
        .upstream
        .request(parts.method, url)
        .headers(headers)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await
        .map_err(|error| {
            warn!(error = %with_causes(&error), "the API cannot be reached");
            StatusCode::BAD_GATEWAY
        })?;
    Ok(relay(response, from_api))
}

/// Everything but `/api/*`: `request` passed to the OAuth agent and its answer back, unchanged but
/// for the connection-only headers.
async fn to_agent(State(state): State<ProxyState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let path_and_query = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
    let url = format!("{}{path_and_query}", state.config.agent_url);
    let mut headers = parts.headers;
    strip_connection_only(&mut headers);

    match state
        .upstream
        .request(parts.method, url)
        .headers(headers)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await
    {
        Ok(response) => relay(response, strip_connection_only),
        Err(error) => {
            warn!(error = %with_causes(&error), "the OAuth agent cannot be reached");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// The browser's response for `upstream`'s: its status, its headers after `rewrite`, and its
/// body streamed.
fn relay(upstream: reqwest::Response, rewrite: fn(&mut HeaderMap)) -> Response {
    let status = upstream.status();
    let mut headers = upstream.headers().clone();
    rewrite(&mut headers);
    let mut response = Response::new(Body::from_stream(upstream.bytes_stream()));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

// What may cross from the browser to the API and back: the API URL for a browser path, and the
// headers that never pass.

/// Headers about a single connection ("hop"), not about the request itself (RFC 9110 §7.6.1):
/// passing them to the next connection would make the API act on settings never meant for it,
/// and a forwarded `transfer-encoding` is how request smuggling works. A sender may also list
/// its own connection-only headers in `Connection`; those go too, then `Connection` itself.
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

/// Headers in which a proxy in front reports who the client is and how it connected. A browser
/// can send any of them, and an API that trusted them could be told anything, so none reaches
/// the API; it gets a single `x-forwarded-for` set by the proxy itself, holding the address it
/// determined (see [`token_handler_common::client_ip::ClientIpSource`]).
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

/// Removes from `headers` the connection-only headers: those a sender listed in `Connection`
/// (e.g. `Connection: x-trace-hop`), then `Connection` itself and [`HOP_BY_HOP`]. For any request
/// or response passing from one connection to the next; the HTTP library frames each
/// connection's body itself.
fn strip_connection_only(headers: &mut HeaderMap) {
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

/// Removes from `headers` every header in which a client or a proxy claims who the client is or
/// how it connected ([`FORWARDING`]).
fn strip_forwarding(headers: &mut HeaderMap) {
    for name in FORWARDING {
        headers.remove(name);
    }
}

/// Turns the browser's request `headers` into the API's: connection-only headers, the browser's
/// credentials (its cookies hold the session; any `Authorization` it sends is replaced), the
/// CSRF header, `Host` (the HTTP client sets the API's) and every forwarding header removed;
/// `x-forwarded-for` set to `client_ip`, which the caller determined from the original headers,
/// and `Authorization` to the session's `token`.
fn to_api(
    headers: &mut HeaderMap,
    client_ip: IpAddr,
    token: &str,
) -> Result<(), InvalidHeaderValue> {
    strip_connection_only(headers);
    for name in [AUTHORIZATION, COOKIE, HOST] {
        headers.remove(name);
    }
    headers.remove(CSRF_HEADER);
    strip_forwarding(headers);
    headers.insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&client_ip.to_string())?,
    );
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    Ok(())
}

/// Turns the API's response `headers` into the browser's: connection-only headers removed, and
/// any `Set-Cookie`, which would land on the app's origin and be sent with every later request
/// there, outside the session's control.
fn from_api(headers: &mut HeaderMap) {
    strip_connection_only(headers);
    headers.remove(SET_COOKIE);
}

/// The API URL for browser path `path` with `query`: the path after `/api`, appended to
/// `api_base_url`. `None` if the path has `.` or `..` segments (also percent-encoded or split
/// by backslashes), which URL parsing or the API might resolve to a path outside the base, or
/// if the result is not under it.
fn api_url(api_base_url: &str, path: &str, query: Option<&str>) -> Option<Url> {
    let path = path.strip_prefix("/api").unwrap_or(path);
    // Decoded the way lenient servers might: `%2e` as `.`, `\\` and `%5c` as `/`.
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
    let query = query.map(|q| format!("?{q}")).unwrap_or_default();
    let base = api_base_url.trim_end_matches('/');
    let url = Url::parse(&format!("{base}{path}{query}")).ok()?;
    url.as_str().starts_with(base).then_some(url)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use axum::{
        Router,
        body::Body,
        extract::ConnectInfo,
        http::{HeaderMap, HeaderValue, Request, StatusCode, header},
        response::IntoResponse,
        routing::get,
    };
    use token_handler_common::client_ip::ClientIpSource;
    use tower::ServiceExt;

    use super::{
        ProxyState, api_url, from_api, router, strip_connection_only, strip_forwarding, to_api,
    };
    use crate::config::Config;

    /// A stand-in OAuth agent on a free local port: `/auth/login` redirects and sets a cookie, as
    /// sign-in does; `/echo` answers with the `Host` and `Cookie` it received. Its URL.
    async fn fake_agent() -> String {
        let app = Router::new()
            .route(
                "/auth/login",
                get(|| async {
                    (
                        StatusCode::FOUND,
                        [
                            (header::LOCATION, "https://keycloak-api/auth?state=1"),
                            (header::SET_COOKIE, "__Host-Http-login=x; Secure"),
                        ],
                    )
                }),
            )
            .route(
                "/echo",
                get(|headers: HeaderMap| async move {
                    let get = |name| {
                        headers
                            .get(name)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned()
                    };
                    format!("{}|{}", get(header::HOST), get(header::COOKIE)).into_response()
                }),
            );
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        url
    }

    /// The proxy in front of the OAuth agent at `agent_url`, with no Redis or API behind it.
    fn proxy(agent_url: String) -> Router {
        let config = Config {
            listen_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            agent_url,
            agent_internal_url: "http://127.0.0.1:1".into(),
            internal_secret: "secret".into(),
            api_base_url: None,
            redis_uri: "redis://127.0.0.1:1".into(),
            client_ip: ClientIpSource::from_settings(None, None).unwrap(),
            metrics_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        };
        router(ProxyState::new(config).unwrap())
    }

    /// `request` from a browser at 127.0.0.1, as the server would see it.
    fn from_browser(request: axum::http::request::Builder) -> Request<Body> {
        request
            .extension(ConnectInfo(SocketAddr::from((Ipv4Addr::LOCALHOST, 50000))))
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn given_sign_in_then_the_agents_redirect_and_cookie_reach_the_browser() {
        let response = proxy(fake_agent().await)
            .oneshot(from_browser(Request::get("/auth/login")))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FOUND, "not followed");
        assert_eq!(
            response.headers()[header::LOCATION],
            "https://keycloak-api/auth?state=1"
        );
        assert_eq!(
            response.headers()[header::SET_COOKIE],
            "__Host-Http-login=x; Secure"
        );
    }

    #[tokio::test]
    async fn given_a_agent_route_then_host_and_cookies_pass_unchanged() {
        let response = proxy(fake_agent().await)
            .oneshot(from_browser(
                Request::get("/echo")
                    .header(header::HOST, "auth-api")
                    .header(header::COOKIE, "__Host-Http-session=sid"),
            ))
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&body[..], b"auth-api|__Host-Http-session=sid");
    }

    #[tokio::test]
    async fn given_an_api_call_without_the_csrf_header_then_it_is_refused_with_an_id() {
        let response = proxy("http://127.0.0.1:1".into())
            .oneshot(from_browser(
                Request::get("/api/orders").header(header::COOKIE, "__Host-Http-session=sid"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().contains_key("x-request-id"));
    }

    #[tokio::test]
    async fn given_an_api_call_without_a_session_cookie_then_it_is_unauthorized() {
        let response = proxy("http://127.0.0.1:1".into())
            .oneshot(from_browser(
                Request::get("/api/orders").header("x-csrf", "1"),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn given_the_agent_is_down_then_the_browser_gets_a_bad_gateway() {
        let response = proxy("http://127.0.0.1:1".into())
            .oneshot(from_browser(Request::get("/auth/session")))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    const BASE: &str = "http://api.internal/v1";

    fn target(path: &str, query: Option<&str>) -> Option<String> {
        api_url(BASE, path, query).map(String::from)
    }

    #[test]
    fn given_an_api_path_then_it_maps_under_the_base_with_its_query() {
        assert_eq!(
            target("/api/orders/7", Some("page=2")).as_deref(),
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
            assert_eq!(target(path, None), None, "{path}");
        }
    }

    #[test]
    fn given_dots_inside_a_segment_then_the_path_is_kept() {
        assert_eq!(
            target("/api/files/report..final.pdf", None).as_deref(),
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

    #[test]
    fn given_connection_headers_then_they_and_the_listed_ones_go() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "connection",
            HeaderValue::from_static("keep-alive, x-trace-hop"),
        );
        for name in ["x-trace-hop", "keep-alive", "transfer-encoding", "upgrade"] {
            headers.insert(name, HeaderValue::from_static("1"));
        }
        headers.insert("content-length", HeaderValue::from_static("2"));

        strip_connection_only(&mut headers);

        let left: Vec<&str> = headers.keys().map(|name| name.as_str()).collect();
        assert_eq!(left, ["content-length"]);
    }

    #[test]
    fn given_a_browser_request_then_the_api_gets_the_token_and_no_credentials() {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("cookie", "__Host-Http-session=sid"),
            ("authorization", "Bearer forged"),
            ("x-csrf", "1"),
            ("host", "auth-api"),
            ("x-forwarded-for", "203.0.113.9"),
            ("accept", "application/json"),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }

        to_api(
            &mut headers,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            "t0ken",
        )
        .unwrap();

        for gone in ["cookie", "x-csrf", "host"] {
            assert!(!headers.contains_key(gone), "{gone} reached the API");
        }
        assert_eq!(headers["authorization"], "Bearer t0ken");
        assert_eq!(headers["x-forwarded-for"], "198.51.100.7");
        assert_eq!(headers["accept"], "application/json");
    }

    #[test]
    fn given_an_api_response_then_its_cookies_never_reach_the_browser() {
        let mut headers = HeaderMap::new();
        headers.insert("set-cookie", HeaderValue::from_static("tracking=1"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        from_api(&mut headers);

        assert!(!headers.contains_key("set-cookie"));
        assert_eq!(headers["content-type"], "application/json");
    }
}
