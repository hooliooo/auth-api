use axum::http::{StatusCode, header::InvalidHeaderValue};
use axum::response::{IntoResponse, Response};
use oidc::OidcSetupError;
use redis::RedisError;
use thiserror::Error;
use tracing::{debug, error};

use crate::auth::LoginError;
use crate::random::RandomUnvailable;

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Header(InvalidHeaderValue),
    #[error(transparent)]
    Json(serde_json::Error),
    #[error("Login error: '{0}'")]
    LoginError(LoginError),
    #[error(transparent)]
    Redis(RedisError),
    #[error("Not signed in")]
    Unauthorized,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::LoginError(_) | AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if status.is_server_error() {
            error!(error = %self, "request failed");
        } else {
            debug!(error = %self, "request failed")
        }
        status.into_response()
    }
}

impl From<InvalidHeaderValue> for AppError {
    fn from(value: InvalidHeaderValue) -> Self {
        AppError::Header(value)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(value: serde_json::Error) -> Self {
        AppError::Json(value)
    }
}

impl From<LoginError> for AppError {
    fn from(value: LoginError) -> Self {
        AppError::LoginError(value)
    }
}

impl From<RandomUnvailable> for AppError {
    fn from(value: RandomUnvailable) -> Self {
        AppError::LoginError(LoginError::RandomError(value))
    }
}

impl From<RedisError> for AppError {
    fn from(value: RedisError) -> Self {
        AppError::Redis(value)
    }
}

#[derive(Debug, Error)]
pub enum StartupError {
    #[error("missing env var '{0}'")]
    MissingEnv(String),
    #[error("invalid URL in {0}")]
    InvalidUrl(&'static str),
    #[error(transparent)]
    Oidc(#[from] OidcSetupError),
}
