//! The axum side of authentication: pulling a bearer token off a request and turning a
//! verification failure into a response. The verification itself lives in the
//! [`authentication`] crate, which knows nothing about HTTP.

use std::sync::Arc;

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
    response::IntoResponse,
};
use axum_extra::headers::{Authorization, HeaderMapExt, authorization::Bearer};

pub use authentication::{
    Claims, ClaimsExtractor, JwtVerificationError, JwtVerifier, KeycloakJwtVerifier,
    WellKnownEndpointError,
};

/// Application state that can hand out a [`JwtVerifier`], so the extractor can reach one from
/// any handler.
pub trait JwtVerifierState {
    fn jwt_verifier(&self) -> Arc<dyn JwtVerifier>;
}

/// A request that carried a valid bearer token.
pub struct Authenticated(pub Claims);

impl<S> FromRequestParts<S> for Authenticated
where
    S: JwtVerifierState,
    S: Send + Sync,
{
    type Rejection = JwtHeaderError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if !parts.headers.contains_key(AUTHORIZATION) {
            return Err(JwtHeaderError::MissingAuthorizationHeader);
        }

        let Authorization(bearer) = parts
            .headers
            .typed_get::<Authorization<Bearer>>()
            .ok_or(JwtHeaderError::MissingBearerToken)?;

        let jwt = state
            .jwt_verifier()
            .verify(bearer.token())
            .await
            .map_err(JwtHeaderError::InvalidJwt)?;

        let claims = jwt.extract().map_err(JwtHeaderError::InvalidJwt)?;
        tracing::debug!(client_id = %claims.client_id, "Extracted JWT claims");
        Ok(Self(claims))
    }
}

/// The rejection returned when the [`Authenticated`] extractor cannot produce claims.
pub enum JwtHeaderError {
    MissingAuthorizationHeader,
    MissingBearerToken,
    InvalidJwt(JwtVerificationError),
}

impl IntoResponse for JwtHeaderError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::MissingAuthorizationHeader => {
                (StatusCode::UNAUTHORIZED, "Authorization required").into_response()
            }
            Self::MissingBearerToken => {
                (StatusCode::UNAUTHORIZED, "Bearer token required").into_response()
            }
            Self::InvalidJwt(verification_error) => (
                StatusCode::UNAUTHORIZED,
                format!("Invalid Jwt: {:?}", verification_error),
            )
                .into_response(),
        }
    }
}
