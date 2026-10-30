//! Errors: per request ([`AppError`]) and at startup ([`StartupError`]).

use axum::http::{StatusCode, header::InvalidHeaderValue, header::RETRY_AFTER};
use axum::response::{IntoResponse, Response};
use redis::RedisError;
use thiserror::Error;
use tracing::{debug, error};

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
    // /// Sign-in, logout or token checks failed.
    // #[error("Login error: '{0}'")]
    // LoginError(LoginError),
    /// `/api/*` was called but no API is configured.
    #[error("No API URL configured")]
    NoApiUrl,
    /// The API could not be reached.
    #[error("Proxy request error: '{0}'")]
    ProxyRequestFailed(String),
    #[error("Random generator failed")]
    RandomGenerationFailed,
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
    /// The BFF could not authenticate itself to the identity provider.
    #[error(transparent)]
    ClientCredentials(#[from] crate::client::credentials::ClientAssertionError),
    /// An `/api/*` path that would leave the API's base URL, e.g. through `..`.
    #[error("API path not allowed")]
    InvalidApiPath,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        #[cfg(feature = "rate-limit")]
        if let AppError::TooManyRequests { retry_after } = self {
            use tracing::debug;

            debug!(retry_after, "rate limited");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(RETRY_AFTER, retry_after.to_string())],
            )
                .into_response();
        }
        let status = status_of(&self);
        if status.is_server_error() {
            error!(error = %self, "request failed");
        } else {
            debug!(error = %self, "request failed")
        }
        status.into_response()
    }
}

/// The status `error` answers with: 4xx for the client's mistakes, 502 when the API or the
/// identity provider failed, 503 when Redis or the API configuration is missing, 500 for the
/// BFF's own failures.
fn status_of(error: &AppError) -> StatusCode {
    match error {
        AppError::Unauthorized => StatusCode::UNAUTHORIZED,
        AppError::InvalidApiPath => StatusCode::BAD_REQUEST,
        AppError::ProxyRequestFailed(_) | AppError::RefreshAccessTokenFailed(_) => {
            StatusCode::BAD_GATEWAY
        }
        AppError::Redis(_) | AppError::NoApiUrl => StatusCode::SERVICE_UNAVAILABLE,
        #[cfg(feature = "rate-limit")]
        AppError::TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
        AppError::Header(_)
        | AppError::Json(_)
        | AppError::Response(_)
        | AppError::ClientCredentials(_)
        | AppError::RandomGenerationFailed => StatusCode::INTERNAL_SERVER_ERROR,
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

// impl From<LoginError> for AppError {
//     fn from(value: LoginError) -> Self {
//         AppError::LoginError(value)
//     }
// }
//
impl From<RandomUnvailable> for AppError {
    fn from(_value: RandomUnvailable) -> Self {
        AppError::RandomGenerationFailed
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
    /// `REDIRECT_URI` is not HTTPS and plain HTTP was not allowed.
    #[error("REDIRECT_URI must be https unless ALLOW_INSECURE_HTTP=true")]
    InsecureRedirectUri,
    /// `OIDC_SCOPES` cannot be used; holds why.
    #[error("invalid OIDC_SCOPES: {0}")]
    InvalidScopes(&'static str),
    /// A setting has a value that cannot be used.
    #[error("invalid value in {0}")]
    InvalidSetting(&'static str),
    /// A configured or discovered URL does not parse.
    #[error("invalid URL in {0}")]
    InvalidUrl(&'static str),
    /// A required environment variable is not set.
    #[error("missing env var '{0}'")]
    MissingEnv(String),
    /// The identity provider could not be set up: its discovery document, issuer or signing keys.
    #[error(transparent)]
    Oidc(#[from] oidc::OidcVerifierError),
    /// `CLIENT_IP_HEADER` is set without `TRUSTED_PROXIES`.
    #[error("CLIENT_IP_HEADER needs TRUSTED_PROXIES: the proxies allowed to set it")]
    UntrustedClientIpHeader,
}
