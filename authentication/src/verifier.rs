use crate::{claims::Claims, error::JwtVerificationError};

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
