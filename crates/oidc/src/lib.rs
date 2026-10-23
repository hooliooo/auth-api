//! Verifies tokens from an OpenID Connect provider.
//!
//! - [`OidcVerifier`] and its errors and traits: discovery, signing keys, token checks.
//! - [`logout`]: the extra checks for back-channel logout tokens.
//! - [`well_known`]: the discovery document and which URL schemes are accepted.
//!
//! The provider's signing keys and their cache are internal; only [`JwksSourceError`], part of
//! [`OidcVerifierError`], is public.
#![warn(missing_docs)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

mod jwks;
pub mod logout;
mod retry;
mod verifier;
pub mod well_known;

pub use jwks::JwksSourceError;
pub use verifier::{
    LEEWAY_SECS, OidcVerifier, OidcVerifierError, ProviderClaims, VerificationError, Verifier,
};
