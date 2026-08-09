use kern::application::request::Request;

use crate::domain::authorization::AuthUserId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizedScope {
    SuperAdmin,
    OrganizationAdmin,
    User,
}

pub trait AuthorizedScopeRequest: Request {
    fn auth_user_id(&self) -> &AuthUserId;
    fn authorized_scope(&self) -> &AuthorizedScope;
}
