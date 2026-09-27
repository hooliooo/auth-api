//! Implements the core's authentication port against an OpenID Connect provider.
//!
//! [`oidc`] holds what every OIDC provider shares: discovery, JWKS signature checks and the
//! standard validations. Each provider adds only how its claims are read, e.g. [`keycloak`].

mod cache;
pub mod keycloak;
pub mod oidc;

pub use keycloak::{Keycloak, KeycloakJwtVerifier};
pub use oidc::{
    OidcJwtVerifier, OidcSetupError, ProviderClaims, WellKnownEndpoint, WellKnownEndpointError,
};
