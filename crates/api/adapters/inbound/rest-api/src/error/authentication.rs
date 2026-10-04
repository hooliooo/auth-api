//! Rejected bearer tokens, and their translations.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use oidc::oidc::JwtVerificationError;

use super::{ApiError, IntoApiError};

/// The rejection returned when the [`Authenticated`](crate::auth::Authenticated) extractor
/// cannot produce claims.
pub enum JwtHeaderError {
    MissingAuthorizationHeader,
    MissingBearerToken,
    InvalidJwt(JwtVerificationError),
    /// The token is valid, but its subject is not a user id this service accepts
    UnsupportedSubject,
}

impl IntoApiError for JwtHeaderError {
    fn into_api_error(self) -> ApiError {
        match self {
            Self::MissingAuthorizationHeader => ApiError::new(
                StatusCode::UNAUTHORIZED,
                "error.authentication.missing-authorization-header",
                "Authorization required",
            ),
            Self::MissingBearerToken => ApiError::new(
                StatusCode::UNAUTHORIZED,
                "error.authentication.missing-bearer-token",
                "Bearer token required",
            ),
            // The provider could not be asked: the token may be fine, the service is not
            Self::InvalidJwt(JwtVerificationError::ProviderUnavailable(reason)) => {
                tracing::error!(%reason, "Unable to reach the identity provider to verify a token");
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "error.authentication.unavailable",
                    "Unable to verify token",
                )
            }
            // The details stay in the logs; they describe the verifier, not anything to fix
            Self::InvalidJwt(verification_error) => {
                tracing::debug!(error = %verification_error, "Rejected token");
                ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "error.authentication.invalid-token",
                    "Invalid token",
                )
            }
            Self::UnsupportedSubject => ApiError::new(
                StatusCode::UNAUTHORIZED,
                "error.authentication.unsupported-subject",
                "Token subject is not a valid user id",
            ),
        }
    }
}

/// `Authenticated` is also used on its own as an extractor, where axum needs the rejection to
/// be a response.
impl IntoResponse for JwtHeaderError {
    fn into_response(self) -> Response {
        self.into_api_error().into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use oidc::oidc::JwtVerificationError;

    use crate::error::{authentication::JwtHeaderError, test_support::render};

    #[tokio::test]
    async fn given_a_rejected_token_when_rendered_then_it_should_hide_the_details() {
        let error = JwtVerificationError::Invalid("ExpiredSignature at 1700000000".into());
        let (status, body) = render(JwtHeaderError::InvalidJwt(error)).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body.error_key, "error.authentication.invalid-token");
        assert!(!body.description.contains("ExpiredSignature"));
    }

    #[tokio::test]
    async fn given_an_unreachable_provider_when_rendered_then_it_should_be_unavailable() {
        let (status, body) = render(JwtHeaderError::InvalidJwt(
            JwtVerificationError::ProviderUnavailable("connection refused".into()),
        ))
        .await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.error_key, "error.authentication.unavailable");
    }
}
