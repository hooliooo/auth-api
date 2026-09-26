//! Implements the core's authentication port against an OpenID Connect provider.
//!
//! [`oidc`] holds what every OIDC provider shares: discovery, JWKS signature checks and the
//! standard validations. Each provider adds only how its claims are read, e.g. [`keycloak`].

pub mod keycloak;
pub mod oidc;

pub use keycloak::{KeycloakClaims, KeycloakJwtVerifier};
pub use oidc::{OidcJwtVerifier, ProviderClaims, WellKnownEndpoint, WellKnownEndpointError};
