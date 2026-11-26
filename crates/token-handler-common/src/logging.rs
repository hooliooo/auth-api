//! Logging, the same way in both services: what is logged where, at which level, and how an outage
//! of a dependency is reported without repeating itself.
//!
//! - **Format:** `LOG_FORMAT=json` writes one JSON object per line, with the request's span fields
//!   (its id, method and path) on every event, for a log pipeline; `text` (the default) is for
//!   people, coloured only on a terminal.
//! - **Levels:** `RUST_LOG` filters, `info` by default. `error` is for failures of the service
//!   itself, `warn` for a dependency or the identity provider misbehaving, `info` for events worth
//!   seeing in a quiet log (startup, recoveries, a session ended by the provider), `debug` for
//!   routine refusals of a browser's request. Successful requests log nothing: the metrics count
//!   them.
//! - **Never logged:** tokens, cookies, session ids, query strings and secrets.

use std::{
    io::IsTerminal,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

/// How log lines are written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    /// For people.
    Text,
    /// One JSON object per line.
    Json,
}

/// The format `LOG_FORMAT` value `setting` asks for: unset is `text`; an unknown value is returned
/// as the error, to be reported once logging works.
fn format_from(setting: Option<&str>) -> Result<Format, String> {
    match setting {
        None | Some("text") => Ok(Format::Text),
        Some("json") => Ok(Format::Json),
        Some(other) => Err(other.to_owned()),
    }
}

/// Sets up logging from `RUST_LOG` (default `info`) and `LOG_FORMAT`, and logs panics through it.
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let setting = std::env::var("LOG_FORMAT").ok();
    let format = format_from(setting.as_deref());
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match format {
        Ok(Format::Json) => builder
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(false)
            .init(),
        Ok(Format::Text) | Err(_) => builder.with_ansi(std::io::stdout().is_terminal()).init(),
    }
    if let Err(value) = format {
        warn!(
            value,
            "unknown LOG_FORMAT, logging as text; use text or json"
        );
    }
    log_panics();
}

/// Logs a panic as an error event, with the request's span fields when it happens in a request,
/// instead of unformatted text beside the log.
fn log_panics() {
    std::panic::set_hook(Box::new(|info| {
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "a panic without a message".to_owned());
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        let backtrace = std::backtrace::Backtrace::capture();
        if backtrace.status() == std::backtrace::BacktraceStatus::Captured {
            error!(panic = %payload, %location, %backtrace, "panicked");
        } else {
            error!(panic = %payload, %location, "panicked");
        }
    }));
}

/// A dependency's availability, for logging its outages once: the first failure is a warning,
/// later ones are `debug` and counted, and the first success after them says it is back and how
/// many failures there were. Without it, a Redis outage logs a warning on every request and every
/// readiness probe. Kept in a `static`, one per dependency.
pub struct Outage {
    /// The dependency's name, as logged.
    dependency: &'static str,
    /// Whether it is failing now.
    down: AtomicBool,
    /// Failures since the outage began.
    failures: AtomicU64,
}

impl Outage {
    /// The availability of `dependency`, up until something fails.
    pub const fn new(dependency: &'static str) -> Self {
        Self {
            dependency,
            down: AtomicBool::new(false),
            failures: AtomicU64::new(0),
        }
    }

    /// Records a failure with `error`; `true` if it began an outage and was logged as a warning.
    pub fn failed(&self, error: &str) -> bool {
        self.failures.fetch_add(1, Ordering::AcqRel);
        let began = !self.down.swap(true, Ordering::AcqRel);
        if began {
            warn!(dependency = self.dependency, error, "unavailable");
        } else {
            debug!(dependency = self.dependency, error, "still unavailable");
        }
        began
    }

    /// Records a success; the failures counted if it ended an outage, which is then logged.
    pub fn ok(&self) -> Option<u64> {
        if !self.down.load(Ordering::Acquire) || !self.down.swap(false, Ordering::AcqRel) {
            return None;
        }
        let failures = self.failures.swap(0, Ordering::AcqRel);
        info!(dependency = self.dependency, failures, "available again");
        Some(failures)
    }
}

#[cfg(test)]
mod tests {
    use super::{Format, Outage, format_from};

    #[test]
    fn given_the_log_format_setting_then_text_is_the_default_and_others_are_refused() {
        assert_eq!(format_from(None), Ok(Format::Text));
        assert_eq!(format_from(Some("text")), Ok(Format::Text));
        assert_eq!(format_from(Some("json")), Ok(Format::Json));
        assert_eq!(format_from(Some("JSON")), Err("JSON".to_owned()));
    }

    #[test]
    fn given_an_outage_then_it_is_reported_once_when_it_begins_and_once_when_it_ends() {
        let redis = Outage::new("redis");
        assert_eq!(redis.ok(), None, "nothing to recover from");
        assert!(
            redis.failed("refused"),
            "the first failure begins the outage"
        );
        assert!(!redis.failed("refused"));
        assert!(!redis.failed("refused"));
        assert_eq!(redis.ok(), Some(3), "the recovery counts every failure");
        assert_eq!(redis.ok(), None, "and is reported once");
        assert!(redis.failed("refused"), "a new failure begins a new outage");
    }
}
