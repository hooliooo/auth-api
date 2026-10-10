//! Reading required environment variables.

use crate::error::StartupError;

/// The required environment variable `name`.
pub fn env(name: &str) -> Result<String, StartupError> {
    std::env::var(name).map_err(|_| StartupError::MissingEnv(name.to_owned()))
}
