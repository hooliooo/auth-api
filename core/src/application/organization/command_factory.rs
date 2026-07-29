use std::collections::{HashMap, HashSet};

use kern::{
    application::{environment::Environment, ids::AuthorizedParty},
    building_blocks::error::domain_error::DomainError,
};
use uuid::Uuid;

use crate::{
    application::organization::commands::CreateOrganization,
    domain::{
        authorization::authorized_scope::AuthorizedScope,
        organization::INVALID_ORGANIZATION_ID_ERROR, user::INVALID_USER_ID_ERROR,
    },
};

#[derive(Clone)]
pub struct OrganizationCommandFactory {
    environment: Environment,
}

impl OrganizationCommandFactory {
    pub fn new(environment: Environment) -> Self {
        Self { environment }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &self,
        id: String,
        name: String,
        display_name: String,
        attributes: HashMap<String, Vec<String>>,
        authorized_party: AuthorizedParty,
        auth_user_id: String,
        authorized_scope: AuthorizedScope,
    ) -> Result<CreateOrganization, DomainError> {
        let Ok(id) = Uuid::try_from(id) else {
            return Err(DomainError::single(INVALID_ORGANIZATION_ID_ERROR));
        };

        let Ok(user_id) = Uuid::try_from(auth_user_id) else {
            return Err(DomainError::single(INVALID_USER_ID_ERROR));
        };

        let attributes = attributes
            .into_iter()
            .map(|(key, value)| (key, value.into_iter().collect::<HashSet<String>>()))
            .collect();

        Ok(CreateOrganization::new(
            id,
            name,
            display_name,
            attributes,
            Uuid::new_v4(),
            self.environment,
            authorized_party,
            user_id,
            authorized_scope,
        ))
    }
}
