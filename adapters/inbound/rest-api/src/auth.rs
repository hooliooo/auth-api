//! The axum side of authentication: pulling a bearer token off a request and turning its
//! claims into the core's authorization context. Verifying the token lives in the
//! [`authentication`] crate, which knows nothing about HTTP; deciding what the caller may do
//! lives in the core.

use std::sync::Arc;

use auth_core::application::authentication::{Claims, JwtVerifier};

mod context;
mod extractor;

pub use context::authz_context;

/// A request that carried a valid bearer token.
pub struct Authenticated(pub Claims);

/// Application state that can hand out a [`JwtVerifier`], so the extractor can reach one from
/// any handler.
pub trait JwtVerifierState {
    fn jwt_verifier(&self) -> Arc<dyn JwtVerifier>;
}
