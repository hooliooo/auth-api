//! The authentication port: verifying a caller's bearer token and reading the claims this
//! service acts on. Implemented by an outbound adapter per identity provider; nothing here
//! knows how a provider verifies its tokens.

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
