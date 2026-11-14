//! The CSRF header (RFC 10017 §6.1.3.3.2), required on every call the session cookie authorizes,
//! whatever its method: the OAuth proxy's `/api/*` and the OAuth agent's session routes. The
//! session cookie is `SameSite=Strict`, so other sites cannot send it; but a page on another
//! subdomain of the same site can, and a `GET` is sent without a CORS preflight. The header closes
//! that gap: no page of another origin can add it without a preflight, which is never granted.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Which paths need the header: each service's own rule.
pub type PathRule = fn(&str) -> bool;

/// Header the app must send with a value of `1` on every call the session cookie authorizes.
pub const CSRF_HEADER: &str = "x-csrf";

/// Whether header value `value` is the CSRF header's only accepted value, `1`.
fn is_present(value: Option<&[u8]>) -> bool {
    value == Some(b"1".as_slice())
}

/// Middleware: refuses `request` with 403 if `needs` says its path needs the header and it is
/// missing, otherwise passes it to `next`. Use with
/// `axum::middleware::from_fn_with_state(rule, require_header)`.
pub async fn require_header(
    State(needs): State<PathRule>,
    request: Request,
    next: Next,
) -> Response {
    let present = is_present(request.headers().get(CSRF_HEADER).map(|v| v.as_bytes()));
    if needs(request.uri().path()) && !present {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}
