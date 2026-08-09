use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use kern::{
    Request,
    application::{
        environment::Environment,
        ids::{AuthorizedParty, RequestId},
    },
};
use uuid::Uuid;

use crate::domain::{
    authorization::{
        AuthUserId,
        authorized_scope::{AuthorizedScope, AuthorizedScopeRequest},
    },
    organization::OrganizationId,
};

#[derive(Request, Debug, Clone)]
pub struct CreateOrganization {
    aggregate_id: OrganizationId,
    name: String,
    display_name: String,
    description: String,
    is_enabled: bool,
    attributes: HashMap<String, HashSet<String>>,
    request_id: RequestId,
    environment: Environment,
    issued_at: DateTime<Utc>,
    authorized_party: AuthorizedParty,
    auth_user_id: AuthUserId,
    authorized_scope: AuthorizedScope,
}

impl CreateOrganization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        aggregate_id: Uuid,
        name: String,
        display_name: String,
        description: String,
        is_enabled: bool,
        attributes: HashMap<String, HashSet<String>>,
        request_id: Uuid,
        environment: Environment,
        authorized_party: AuthorizedParty,
        auth_user_id: Uuid,
        authorized_scope: AuthorizedScope,
    ) -> Self {
        CreateOrganization {
            aggregate_id: OrganizationId::new(aggregate_id),
            name,
            display_name,
            description,
            is_enabled,
            attributes,
            request_id: RequestId::new(request_id),
            environment,
            issued_at: Utc::now(),
            authorized_party,
            auth_user_id: AuthUserId::new(auth_user_id),
            authorized_scope,
        }
    }

    pub fn aggregate_id(&self) -> &OrganizationId {
        &self.aggregate_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    pub fn attributes(&self) -> &HashMap<String, HashSet<String>> {
        &self.attributes
    }
}

impl AuthorizedScopeRequest for CreateOrganization {
    fn auth_user_id(&self) -> &AuthUserId {
        &self.auth_user_id
    }

    fn authorized_scope(&self) -> &AuthorizedScope {
        &self.authorized_scope
    }
}
