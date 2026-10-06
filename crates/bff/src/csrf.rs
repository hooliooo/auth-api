use axum::{
    extract::Request,
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

pub const CSRF_HEADER: &str = "x-bff-csrf";
const EXEMPT_PATHS: &[&str] = &["/auth/backchannel-logout"];

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
