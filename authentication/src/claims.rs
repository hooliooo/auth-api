use auth_core::domain::authorization::authorized_scope::AuthorizedScope;

/// The claims this service acts on, read from a verified token.
#[derive(Clone, Debug)]
pub struct Claims {
    pub client_id: String,
    pub user_id: String,
    pub authorized_scope: AuthorizedScope,
}
