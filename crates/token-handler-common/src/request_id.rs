//! Request ids: kept from the caller when they look like one (e.g. Cloudflare's), otherwise
//! new, and carried to the API and back on the response, so one user's problem can be followed
//! across services.

use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use tracing::{Instrument, info_span};

use crate::random::random_token;

/// Header carrying the request id.
const REQUEST_ID_HEADER: &str = "x-request-id";

/// Whether an incoming `id` looks like a request id and may be kept; anything else is
/// replaced, so a client cannot write arbitrary text into the logs.
fn acceptable(id: &str) -> bool {
    (8..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The id for a request that arrived with `incoming`: that one if acceptable, a new one
/// otherwise.
fn assign(incoming: Option<&str>) -> String {
    incoming
        .filter(|id| acceptable(id))
        .map(str::to_owned)
        .or_else(|| random_token().ok())
        .unwrap_or_else(|| "unavailable".to_owned())
}

/// Middleware: gives `request` an id, runs `next` inside a tracing span carrying it, and
/// returns the id on the response. The request keeps it too, so a proxied call carries it on.
pub async fn middleware(mut request: Request, next: Next) -> Response {
    let id = assign(
        request
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|v| v.to_str().ok()),
    );
    let value = HeaderValue::from_str(&id).unwrap_or(HeaderValue::from_static("unavailable"));
    request
        .headers_mut()
        .insert(REQUEST_ID_HEADER, value.clone());

    let span = info_span!(
        "request",
        id = %id,
        method = %request.method(),
        path = %request.uri().path(),
    );
    let mut response = next.run(request).instrument(span).await;
    response.headers_mut().insert(REQUEST_ID_HEADER, value);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_an_id_like_value_then_it_is_kept() {
        assert!(acceptable("8f14e45f-ceea-467a"));
        assert!(acceptable("Ab_12345"));
        assert_eq!(
            assign(Some("trace-from-cloudflare-123")),
            "trace-from-cloudflare-123"
        );
    }

    #[test]
    fn given_text_that_is_not_an_id_then_it_is_replaced() {
        assert!(!acceptable("short"));
        assert!(!acceptable("has spaces in it"));
        assert!(!acceptable("line\nbreak-injection"));
        assert!(!acceptable(&"x".repeat(65)));
        assert_ne!(assign(Some("not an id")), "not an id");
    }
}
