//! Logging setup.

use tracing_subscriber::EnvFilter;

/// Logs to stdout at `info` unless `RUST_LOG` says otherwise; the default would drop every
/// warning.
pub fn init() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}
