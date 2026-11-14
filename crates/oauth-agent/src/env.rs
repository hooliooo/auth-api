//! Reading settings from the environment.

use std::str::FromStr;

use crate::error::StartupError;

/// The required environment variable `name`.
pub fn env(name: &str) -> Result<String, StartupError> {
    std::env::var(name).map_err(|_| StartupError::MissingEnv(name.to_owned()))
}

/// The optional environment variable `name` read as a `T`, or `default` when it is not set.
pub fn parsed_or<T: FromStr>(name: &'static str, default: T) -> Result<T, StartupError> {
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|_| StartupError::InvalidSetting(name)),
        Err(_) => Ok(default),
    }
}
