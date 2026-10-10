use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue,
        header::{AUTHORIZATION, CONNECTION, COOKIE, HOST, SET_COOKIE},
    },
    response::Response,
    routing::any,
};

use std::net::SocketAddr;

use axum::extract::ConnectInfo;

use crate::{
    client_ip::client_ip,
    csrf::CSRF_HEADER,
    error::AppError,
    session::{CurrentSession, refresh_access_token},
    state::AppState,
};

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

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/{*rest}", any(api))
}

/// Headers a browser could use to claim another address or scheme; the API only ever sees
/// the X-Forwarded-For the BFF sets itself.
const FORWARDING: [&str; 7] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "cf-connecting-ip",
    "true-client-ip",
];

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
    let path_and_query = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let url = format!(
        "{}{}",
        api_base_url,
        path_and_query
            .strip_prefix("/api")
            .unwrap_or(path_and_query)
    );

    let mut headers = parts.headers;
    strip_hop_by_hop(&mut headers);
    for name in [AUTHORIZATION, COOKIE, HOST] {
        headers.remove(name);
    }
    headers.remove(CSRF_HEADER);
    let client = client_ip(&headers, peer, app_state.client_ip_header.as_ref());
    for name in FORWARDING {
        headers.remove(name);
    }
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
    response_headers.remove(SET_COOKIE);

    if let Some(headers) = response.headers_mut() {
        headers.extend(response_headers);
    }

    Ok(response.body(Body::from_stream(api_response.bytes_stream()))?)
}

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
