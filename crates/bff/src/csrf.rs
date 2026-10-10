//! Cross-site request forgery protection: a custom header on every state-changing request.

use axum::{
    extract::Request,
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Header every state-changing request must send with value `1`. Browsers only let
/// cross-site pages send custom headers after a CORS preflight, which the BFF never grants.
pub const CSRF_HEADER: &str = "x-bff-csrf";
/// Paths called server-to-server rather than by the browser, so without the header.
const EXEMPT_PATHS: &[&str] = &["/auth/backchannel-logout"];

/// Middleware: refuses `request` with 403 if it changes state without the CSRF header,
/// otherwise passes it to `next`.
pub async fn require_header(request: Request, next: Next) -> Response {
    let safe = matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );

    let exempt = EXEMPT_PATHS.contains(&request.uri().path());
    let present = request
        .headers()
        .get(CSRF_HEADER)
        .is_some_and(|v| v.as_bytes() == b"1");

    if !safe && !exempt && !present {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}
