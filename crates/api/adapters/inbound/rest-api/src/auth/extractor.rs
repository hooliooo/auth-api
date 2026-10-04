use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts},
};
use axum_extra::headers::{Authorization, HeaderMapExt, authorization::Bearer};

use super::{Authenticated, JwtVerifierState};
use crate::error::authentication::JwtHeaderError;

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

        let claims = state
            .jwt_verifier()
            .verify(bearer.token())
            .await
            .map_err(JwtHeaderError::InvalidJwt)?;

        tracing::debug!(client_id = %claims.client_id, "Extracted JWT claims");
        Ok(Self(claims))
    }
}
