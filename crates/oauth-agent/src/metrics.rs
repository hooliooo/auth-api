//! Prometheus metrics, served on their own address (`METRICS_ADDR`) so they never share the
//! public port. Without the `metrics` feature every recording function is a no-op. The
//! registry and the series are in [`token_handler_common::metrics`], shared with the OAuth proxy.
//!
//! - `token_handler_http_requests_total{route, method, status}` and
//!   `token_handler_http_request_duration_seconds{route, method}`: every request, by route
//!   template.
//! - `token_handler_sign_ins_total{outcome}`: `completed` or `failed`.
//! - `token_handler_token_refreshes_total{outcome}`: `refreshed`, `rejected` (the session ended) or
//!   `failed` (the identity provider was unavailable; the session stays).
//! - `token_handler_logouts_total{provider}`: `ended` at the provider, or `unreachable`.
//! - `token_handler_backchannel_logouts_total{outcome}`: `accepted`, `replayed`, `invalid` or
//!   `provider_unavailable` (its keys could not be fetched to check the token).
//! - `token_handler_rate_limited_total`: sign-in starts refused by the rate limit.

#[cfg(feature = "metrics")]
pub use token_handler_common::metrics::{serve, track};

/// Adds one to counter `name` with `labels`. Without the `metrics` feature it does nothing, so
/// callers need no `cfg` of their own.
pub fn counter(name: &'static str, labels: &[(&'static str, &str)]) {
    #[cfg(feature = "metrics")]
    token_handler_common::metrics::count(name, labels);
    #[cfg(not(feature = "metrics"))]
    let _ = (name, labels);
}
