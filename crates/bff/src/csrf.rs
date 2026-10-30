//! Cross-site request forgery protection: a custom header on every request the session cookie
//! authorizes (RFC 10017 §6.1.3.3.2), whatever its method.
//!
//! The session cookie is `SameSite=Strict`, so other sites cannot send it; but a page on
//! another subdomain of the same site can, and a `GET` is sent without a CORS preflight. The
//! header closes that gap: no page of another origin can add it without a preflight, which the
//! BFF never grants.

use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use reqwest::StatusCode;

/// Header the app must send with a value of `1` on every call to `/api/*` and `/auth/*`.
pub const CSRF_HEADER: &str = "x-bff-csrf";
/// Routes under the protected prefixes that cannot carry the header: the browser navigates to
/// sign-in and back from the identity provider, and the provider calls back-channel logout
/// server to server, without a session cookie.
const EXEMPT_PATHS: &[&str] = &["/auth/login", "/auth/callback", "/auth/backchannel-logout"];

/// Whether a request for `path` must carry the header: the routes that act on the session.
/// Health checks and the public key set carry no session, so they stay open to probes and to
/// the identity provider.
fn needs_header(path: &str) -> bool {
    (path.starts_with("/api/") || path.starts_with("/auth/")) && !EXEMPT_PATHS.contains(&path)
}

/// Middleware: refuses `request` with 403 if its route needs the CSRF header and it is missing,
/// otherwise passes it to `next`.
pub async fn require_header(request: Request, next: Next) -> Response {
    let present = request
        .headers()
        .get(CSRF_HEADER)
        .is_some_and(|v| v.as_bytes() == b"1");

    if needs_header(request.uri().path()) && !present {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use axum::{Router, body::Body, http::Request, middleware, routing::any};
    use reqwest::StatusCode;
    use tower::ServiceExt;

    use super::{CSRF_HEADER, require_header};

    /// The status of `method` on `path` through the CSRF check, with the header if `with_header`.
    async fn status(method: &str, path: &str, with_header: bool) -> StatusCode {
        let app = Router::new()
            .fallback(any(|| async { StatusCode::OK }))
            .layer(middleware::from_fn(require_header));
        let mut request = Request::builder().method(method).uri(path);
        if with_header {
            request = request.header(CSRF_HEADER, "1");
        }
        app.oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn given_a_session_route_without_the_header_then_every_method_is_refused() {
        for (method, path) in [
            ("GET", "/api/orders"),
            ("HEAD", "/api/orders"),
            ("OPTIONS", "/api/orders"),
            ("POST", "/api/orders"),
            ("GET", "/auth/session"),
            ("POST", "/auth/logout"),
        ] {
            assert_eq!(
                status(method, path, false).await,
                StatusCode::FORBIDDEN,
                "{method} {path}"
            );
            assert_eq!(
                status(method, path, true).await,
                StatusCode::OK,
                "{method} {path} with the header"
            );
        }
    }

    #[tokio::test]
    async fn given_navigations_and_server_calls_then_no_header_is_needed() {
        for (method, path) in [
            ("GET", "/auth/login"),
            ("GET", "/auth/callback"),
            ("POST", "/auth/backchannel-logout"),
            ("GET", "/health"),
            ("GET", "/health/ready"),
            ("GET", "/.well-known/jwks.json"),
        ] {
            assert_eq!(
                status(method, path, false).await,
                StatusCode::OK,
                "{method} {path}"
            );
        }
    }
}
