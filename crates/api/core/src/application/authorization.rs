use chrono::{DateTime, Utc};
use kern::{
    application::{
        error::forbidden_error::ForbiddenError,
        ids::{AuthorizedParty, RequestId},
        request::{AuthenticatedRequest, Request},
    },
    building_blocks::error::error_detail::ErrorDetail,
};
use uuid::Uuid;

use crate::application::authorization::authorized_scope::AuthorizedScope;

pub mod authorized_scope;

#[cfg_attr(test, mockall::automock)]
pub trait AuthorizationService: Send + Sync {
    fn require_realm_admin(&self, request: &AuthzContext) -> Result<(), ForbiddenError>;
}

#[derive(Clone)]
pub struct AuthAPIAuthorizationService;

impl AuthorizationService for AuthAPIAuthorizationService {
    fn require_realm_admin(&self, context: &AuthzContext) -> Result<(), ForbiddenError> {
        match context.authorized_scope() {
            AuthorizedScope::SuperAdmin => Ok(()),
            AuthorizedScope::OrganizationAdmin | AuthorizedScope::User => {
                Err(ForbiddenError::new(NOT_A_REALM_ADMIN))
            }
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
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

pub struct AuthzContext {
    request_id: RequestId,
    issued_at: DateTime<Utc>,
    user_id: AuthUserId,
    authorized_party: AuthorizedParty,
    authorized_scope: AuthorizedScope,
}

impl AuthzContext {
    pub fn new(
        request_id: Uuid,
        user_id: Uuid,
        authorized_party: AuthorizedParty,
        authorized_scope: AuthorizedScope,
    ) -> Self {
        Self {
            request_id: RequestId::new(request_id),
            issued_at: Utc::now(),
            user_id: AuthUserId::new(user_id),
            authorized_party,
            authorized_scope,
        }
    }

    pub fn authorized_scope(&self) -> &AuthorizedScope {
        &self.authorized_scope
    }
}

pub struct AuthorizedRequest<R> {
    context: AuthzContext,
    payload: R,
}

impl<R> AuthorizedRequest<R> {
    pub fn new(context: AuthzContext, payload: R) -> Self {
        Self { context, payload }
    }

    pub fn context(&self) -> &AuthzContext {
        &self.context
    }

    pub fn payload(&self) -> &R {
        &self.payload
    }

    pub fn into_parts(self) -> (AuthzContext, R) {
        (self.context, self.payload)
    }
}

impl<R> Request for AuthorizedRequest<R> {
    type RequestId = RequestId;

    fn request_id(&self) -> &RequestId {
        &self.context.request_id
    }

    fn issued_at(&self) -> &DateTime<Utc> {
        &self.context.issued_at
    }
}

impl<R> AuthenticatedRequest for AuthorizedRequest<R> {
    type UserId = AuthUserId;
    type AuthorizedParty = AuthorizedParty;

    fn user_id(&self) -> &AuthUserId {
        &self.context.user_id
    }

    fn authorized_party(&self) -> &AuthorizedParty {
        &self.context.authorized_party
    }
}
