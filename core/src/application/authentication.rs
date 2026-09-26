//! The authentication port: verifying a caller's bearer token and reading the claims this
//! service acts on. Implemented by an outbound adapter per identity provider; nothing here
//! knows how a provider verifies its tokens.

use thiserror::Error;

use crate::application::authorization::authorized_scope::AuthorizedScope;

/// The claims this service acts on, read from a verified token.
/// Values keep the provider's own format, e.g. `user_id` is whatever the provider uses as
/// the subject.
#[derive(Clone, Debug)]
pub struct Claims {
    pub client_id: String,
    pub user_id: String,
    pub authorized_scope: AuthorizedScope,
}

/// Verifies a raw bearer token against an identity provider.
#[async_trait::async_trait]
pub trait JwtVerifier: Send + Sync {
    async fn verify(
        &self,
        raw_token: &str,
    ) -> Result<Box<dyn ClaimsExtractor>, JwtVerificationError>;
}

/// A verified token, from which the claims this service cares about can be read.
pub trait ClaimsExtractor {
    fn extract(self: Box<Self>) -> Result<Claims, JwtVerificationError>;
}

/// Why a token was not accepted, in terms the application can act on. Adapters map their
/// provider's failures onto these and put the specifics in the message.
#[derive(Debug, Error)]
pub enum JwtVerificationError {
    /// The token is malformed, forged, expired or meant for another audience
    #[error("Invalid token: {0}")]
    Invalid(String),
    /// The identity provider could not be reached to verify the token
    #[error("Identity provider unavailable: {0}")]
    ProviderUnavailable(String),
    /// A verified token lacks a claim this service needs
    #[error("Missing claim: {0}")]
    MissingClaim(&'static str),
}
