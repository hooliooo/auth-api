use kern::{
    application::error::forbidden_error::ForbiddenError,
    building_blocks::error::error_detail::ErrorDetail,
};
use uuid::Uuid;

use crate::domain::authorization::authorized_scope::{AuthorizedScope, AuthorizedScopeRequest};

pub mod authorized_scope;

#[cfg_attr(test, mockall::automock)]
pub trait AuthorizationService: Send + Sync {
    fn require_realm_admin(
        &self,
        request: &dyn AuthorizedScopeRequest<
            RequestId = kern::application::ids::RequestId,
            AuthorizedParty = kern::application::ids::AuthorizedParty,
        >,
    ) -> Result<(), ForbiddenError>;
}

#[derive(Clone)]
pub struct AuthAPIAuthorizationService;

impl AuthorizationService for AuthAPIAuthorizationService {
    fn require_realm_admin(
        &self,
        request: &dyn AuthorizedScopeRequest<
            RequestId = kern::application::ids::RequestId,
            AuthorizedParty = kern::application::ids::AuthorizedParty,
        >,
    ) -> Result<(), ForbiddenError> {
        match request.authorized_scope() {
            AuthorizedScope::RealmAdmin => Ok(()),
            AuthorizedScope::OrganizationAdmin | AuthorizedScope::User => {
                Err(ForbiddenError::new(NOT_A_REALM_ADMIN))
            }
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct AuthUserId(Uuid);

impl AuthUserId {
    pub fn new(id: Uuid) -> Self {
        Self(id)
    }
}

pub const NOT_A_REALM_ADMIN: ErrorDetail = ErrorDetail::new_const(
    "error.authorization.not-realm-admin",
    "Not authorized. User is not a realm-admin",
);
