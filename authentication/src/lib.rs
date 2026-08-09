//! Verifying bearer tokens against an OpenID Connect provider.
//!
//! Deliberately free of any transport: the same verifier serves the REST adapter, a future
//! gRPC one, or anything else that receives a token. Turning a verification failure into a
//! protocol response is the calling adapter's job.

pub mod claims;
pub mod error;
pub mod keycloak;
pub mod oidc;
pub mod verifier;

pub use claims::Claims;
pub use error::JwtVerificationError;
pub use keycloak::{KeycloakClaims, KeycloakJwtVerifier};
pub use oidc::{OidcJwtVerifier, ProviderClaims, WellKnownEndpoint, WellKnownEndpointError};
pub use verifier::{ClaimsExtractor, JwtVerifier};
