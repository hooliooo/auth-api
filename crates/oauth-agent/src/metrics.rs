//! Prometheus metrics, served on their own address (`METRICS_ADDR`) so they never share the
//! public port. Without the `metrics` feature every recording function is a no-op. The registry,
//! the series and what each counts are in [`token_handler_common::metrics`], shared with the
//! OAuth proxy.

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
