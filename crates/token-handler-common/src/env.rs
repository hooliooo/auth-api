//! Reading settings from the environment, the same way in both services.

use std::str::FromStr;

use thiserror::Error;

/// Why a setting cannot be read.
#[derive(Debug, Error)]
pub enum EnvError {
    /// A required variable is not set: its name.
    #[error("missing env var '{0}'")]
    Missing(String),
    /// A variable's value cannot be used: its name.
    #[error("invalid value in {0}")]
    Invalid(&'static str),
}

/// The required variable `name`.
pub fn required(name: &str) -> Result<String, EnvError> {
    std::env::var(name).map_err(|_| EnvError::Missing(name.to_owned()))
}

/// The optional variable `name` read as a `T`, or `default` when it is not set.
pub fn parsed_or<T: FromStr>(name: &'static str, default: T) -> Result<T, EnvError> {
    match std::env::var(name) {
        Ok(value) => value.parse().map_err(|_| EnvError::Invalid(name)),
        Err(_) => Ok(default),
    }
}
