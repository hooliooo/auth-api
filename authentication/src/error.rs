/// A failure verifying a presented token, or reading the claims out of a verified one.
///
/// Part of the [`JwtVerifier`](crate::verifier::JwtVerifier) port, so it carries no transport,
/// provider or JWT-library types. Mapping it to a protocol response belongs to the adapter.
#[derive(Debug)]
pub enum JwtVerificationError {
    InvalidJwt,
    CertsUrlInvalid,
    JwkNotFound,
    InvalidJwk,
    MissingClaim(&'static str),
    ValidationError(String),
}

impl std::fmt::Display for JwtVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJwt => write!(f, "InvalidJwt"),
            Self::CertsUrlInvalid => write!(f, "Certs URL Invalid"),
            Self::JwkNotFound => write!(f, "Jwk Not Found"),
            Self::InvalidJwk => write!(f, "Jwk Unusable"),
            Self::MissingClaim(claim) => write!(f, "Missing Claim: {}", claim),
            Self::ValidationError(message) => write!(f, "Validation Error: {}", message),
        }
    }
}

impl std::error::Error for JwtVerificationError {}
