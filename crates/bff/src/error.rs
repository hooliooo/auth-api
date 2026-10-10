//! Errors: per request ([`AppError`]) and at startup ([`StartupError`]).

#[cfg(feature = "rate-limit")]
use axum::http::header::RETRY_AFTER;
use axum::http::{StatusCode, header::InvalidHeaderValue};
use axum::response::{IntoResponse, Response};
use oidc::OidcSetupError;
use redis::RedisError;
use thiserror::Error;
use tracing::{debug, error};

use crate::auth::LoginError;
use crate::random::RandomUnvailable;

/// Why a request failed; maps to the HTTP status the client sees.
#[derive(Debug, Error)]
pub enum AppError {
    /// A header value could not be built.
    #[error(transparent)]
    Header(InvalidHeaderValue),
    /// A JSON value could not be read or written.
    #[error(transparent)]
    Json(serde_json::Error),
    /// Sign-in, logout or token checks failed.
    #[error("Login error: '{0}'")]
    LoginError(LoginError),
    /// `/api/*` was called but no API is configured.
    #[error("No API URL configured")]
    NoApiUrl,
    /// The API could not be reached.
    #[error("Proxy request error: '{0}'")]
    ProxyRequestFailed(String),
    /// Redis failed.
    #[error(transparent)]
    Redis(RedisError),
    /// The identity provider could not refresh the access token right now.
    #[error("Refreshing access token failed: '{0}'")]
    RefreshAccessTokenFailed(String),
    /// A response could not be built.
    #[error(transparent)]
    Response(axum::http::Error),
    /// The client exceeded the sign-in rate limit.
    #[cfg(feature = "rate-limit")]
    #[error("Too many requests; retry after {retry_after} s")]
    TooManyRequests {
        /// Seconds until the current window ends.
        retry_after: u64,
    },
    /// No valid session.
    #[error("Not signed in")]
    Unauthorized,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        #[cfg(feature = "rate-limit")]
        if let AppError::TooManyRequests { retry_after } = self {
            debug!(retry_after, "rate limited");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(RETRY_AFTER, retry_after.to_string())],
            )
                .into_response();
        }
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

impl From<axum::http::Error> for AppError {
    fn from(value: axum::http::Error) -> Self {
        AppError::Response(value)
    }
}

/// Why the BFF could not start.
#[derive(Debug, Error)]
pub enum StartupError {
    /// A required environment variable is not set.
    #[error("missing env var '{0}'")]
    MissingEnv(String),
    /// A configured or discovered URL does not parse.
    #[error("invalid URL in {0}")]
    InvalidUrl(&'static str),
    /// A setting has a value that cannot be used.
    #[error("invalid value in {0}")]
    InvalidSetting(&'static str),
    /// `REDIRECT_URI` is not HTTPS and plain HTTP was not allowed.
    #[error("REDIRECT_URI must be https unless ALLOW_INSECURE_HTTP=true")]
    InsecureRedirectUri,
    /// `CLIENT_IP_HEADER` is set without `TRUSTED_PROXIES`.
    #[error("CLIENT_IP_HEADER needs TRUSTED_PROXIES: the proxies allowed to set it")]
    UntrustedClientIpHeader,
    /// The identity provider could not be set up.
    #[error(transparent)]
    Oidc(#[from] OidcSetupError),
}
