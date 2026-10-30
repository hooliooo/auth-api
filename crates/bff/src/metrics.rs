//! Prometheus metrics, served on their own address (`METRICS_ADDR`) so they never share the
//! public port. Without the `metrics` feature every recording function is a no-op.
//!
//! - `bff_http_requests_total{route, method, status}` and
//!   `bff_http_request_duration_seconds{route, method}`: every request, by route template.
//! - `bff_sign_ins_total{outcome}`: `completed` or `failed`.
//! - `bff_token_refreshes_total{outcome}`: `refreshed`, `rejected` (the session ended) or
//!   `failed` (the identity provider was unavailable; the session stays).
//! - `bff_logouts_total{provider}`: `ended` at the provider, or `unreachable`.
//! - `bff_backchannel_logouts_total{outcome}`: `accepted`, `replayed` or `invalid`.
//! - `bff_rate_limited_total`: sign-in starts refused by the rate limit.

#[cfg(feature = "metrics")]
pub use imp::{serve, track};

/// Adds one to counter `name` with `labels`. Without the `metrics` feature it does nothing, so
/// callers need no `cfg` of their own.
pub fn counter(name: &'static str, labels: &[(&'static str, &str)]) {
    #[cfg(feature = "metrics")]
    imp::count(name, labels);
    #[cfg(not(feature = "metrics"))]
    let _ = (name, labels);
}

/// The registry, the request middleware and the metrics server; only with the `metrics`
/// feature.
#[cfg(feature = "metrics")]
mod imp {
    use std::{
        collections::BTreeMap,
        fmt::Write,
        net::SocketAddr,
        sync::{LazyLock, Mutex, PoisonError},
        time::Instant,
    };

    use axum::{
        Router,
        extract::{MatchedPath, Request},
        http::{HeaderValue, header::CONTENT_TYPE},
        middleware::Next,
        response::{IntoResponse, Response},
        routing::get,
    };
    use tokio::net::TcpListener;
    use tracing::{info, warn};

    /// Upper bounds of the request duration buckets, in seconds.
    const BUCKETS: [f64; 10] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0];

    /// Every metric's name, Prometheus type and description, in output order.
    const DESCRIPTIONS: [(&str, &str, &str); 7] = [
        (
            "bff_http_requests_total",
            "counter",
            "Requests handled, by route template, method and status.",
        ),
        (
            "bff_http_request_duration_seconds",
            "histogram",
            "Time to answer a request, by route template and method.",
        ),
        (
            "bff_sign_ins_total",
            "counter",
            "Completed and failed sign-ins.",
        ),
        (
            "bff_token_refreshes_total",
            "counter",
            "Access token refreshes at the identity provider, by outcome.",
        ),
        (
            "bff_logouts_total",
            "counter",
            "Logouts, by whether the identity provider session was ended too.",
        ),
        (
            "bff_backchannel_logouts_total",
            "counter",
            "Back-channel logout calls from the identity provider, by outcome.",
        ),
        (
            "bff_rate_limited_total",
            "counter",
            "Sign-in starts refused by the rate limit.",
        ),
    ];

    /// Label names and values of one time series.
    type Labels = Vec<(&'static str, String)>;

    /// One histogram's bucket counts, total count and sum.
    #[derive(Default)]
    struct Histogram {
        /// Observations at or below each of [`BUCKETS`].
        buckets: [u64; BUCKETS.len()],
        /// All observations.
        count: u64,
        /// Sum of all observed values, in seconds.
        sum: f64,
    }

    /// All recorded values.
    #[derive(Default)]
    struct Registry {
        /// Counter values by metric name and labels.
        counters: BTreeMap<(&'static str, Labels), u64>,
        /// Request durations by labels.
        durations: BTreeMap<Labels, Histogram>,
    }

    /// The process-wide registry; the lock is held only to update or copy values.
    static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(Mutex::default);

    /// Runs `f` on the registry, also after a panic elsewhere left the lock poisoned.
    fn with_registry<T>(f: impl FnOnce(&mut Registry) -> T) -> T {
        f(&mut REGISTRY.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Adds one to counter `name` with `labels` in the registry.
    pub(super) fn count(name: &'static str, labels: &[(&'static str, &str)]) {
        let labels = labels
            .iter()
            .map(|(key, value)| (*key, (*value).to_owned()))
            .collect();
        with_registry(|registry| *registry.counters.entry((name, labels)).or_default() += 1);
    }

    /// Middleware: counts `request` and times it through `next`, labelled with the route
    /// template (e.g. `/api/{*rest}`) rather than the actual path, so the number of series stays
    /// bounded.
    pub async fn track(request: Request, next: Next) -> Response {
        let route = request
            .extensions()
            .get::<MatchedPath>()
            .map_or("unmatched", MatchedPath::as_str)
            .to_owned();
        let method = request.method().as_str().to_owned();
        let started = Instant::now();
        let response = next.run(request).await;
        let seconds = started.elapsed().as_secs_f64();

        let status = response.status().as_u16().to_string();
        with_registry(|registry| {
            let labels: Labels = vec![("route", route), ("method", method)];
            let mut with_status = labels.clone();
            with_status.push(("status", status));
            *registry
                .counters
                .entry(("bff_http_requests_total", with_status))
                .or_default() += 1;
            let histogram = registry.durations.entry(labels).or_default();
            for (bound, bucket) in BUCKETS.iter().zip(histogram.buckets.iter_mut()) {
                if seconds <= *bound {
                    *bucket += 1;
                }
            }
            histogram.count += 1;
            histogram.sum += seconds;
        });
        response
    }

    /// `labels` in Prometheus syntax, e.g. `{route="/health",method="GET"}`; empty without labels.
    fn format_labels(labels: &[(&str, String)]) -> String {
        if labels.is_empty() {
            return String::new();
        }
        let pairs: Vec<String> = labels
            .iter()
            .map(|(key, value)| {
                let escaped = value
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n");
                format!("{key}=\"{escaped}\"")
            })
            .collect();
        format!("{{{}}}", pairs.join(","))
    }

    /// Everything recorded so far, in the Prometheus text exposition format.
    pub fn render() -> String {
        with_registry(|registry| {
            let mut out = String::new();
            for (name, kind, help) in DESCRIPTIONS {
                let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
                if kind == "histogram" {
                    for (labels, histogram) in &registry.durations {
                        for (bound, count) in BUCKETS.iter().zip(histogram.buckets) {
                            let mut with_le = labels.clone();
                            with_le.push(("le", bound.to_string()));
                            let _ =
                                writeln!(out, "{name}_bucket{} {count}", format_labels(&with_le));
                        }
                        let mut with_le = labels.clone();
                        with_le.push(("le", "+Inf".to_owned()));
                        let _ = writeln!(
                            out,
                            "{name}_bucket{} {}",
                            format_labels(&with_le),
                            histogram.count
                        );
                        let labels = format_labels(labels);
                        let _ = writeln!(out, "{name}_sum{labels} {}", histogram.sum);
                        let _ = writeln!(out, "{name}_count{labels} {}", histogram.count);
                    }
                } else {
                    for ((counter, labels), value) in &registry.counters {
                        if *counter == name {
                            let _ = writeln!(out, "{name}{} {value}", format_labels(labels));
                        }
                    }
                }
            }
            out
        })
    }

    /// `GET /metrics`.
    async fn metrics() -> Response {
        let mut response = render().into_response();
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4"),
        );
        response
    }

    /// Serves `GET /metrics` on `address` until the process exits; logs if it cannot bind.
    pub async fn serve(address: SocketAddr) {
        let listener = match TcpListener::bind(address).await {
            Ok(listener) => listener,
            Err(error) => {
                warn!(%error, %address, "metrics are not served");
                return;
            }
        };
        info!("Metrics on {address}/metrics");
        let app = Router::new().route("/metrics", get(metrics));
        if let Err(error) = axum::serve(listener, app).await {
            warn!(%error, "metrics server stopped");
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn given_label_values_then_quotes_backslashes_and_newlines_are_escaped() {
            let labels = vec![("route", "a\"b\\c\nd".to_owned())];
            assert_eq!(format_labels(&labels), r#"{route="a\"b\\c\nd"}"#);
            assert_eq!(format_labels(&[]), "");
        }

        #[test]
        fn given_recorded_counters_then_they_render_with_help_type_and_labels() {
            count("bff_sign_ins_total", &[("outcome", "completed")]);
            count("bff_sign_ins_total", &[("outcome", "completed")]);
            let rendered = render();
            assert!(rendered.contains("# TYPE bff_sign_ins_total counter"));
            assert!(rendered.contains("bff_sign_ins_total{outcome=\"completed\"} "));
            assert!(rendered.contains("# TYPE bff_http_request_duration_seconds histogram"));
        }
    }
}
