use kern::{
    application::{
        error::forbidden_error::ForbiddenError, event::EventPublisher, use_case::UseCase,
    },
    building_blocks::entity::Entity,
    building_blocks::error::domain_error::DomainError,
};

use crate::{
    application::organization::commands::CreateOrganization,
    domain::{
        authorization::AuthorizationService,
        exception::RepositoryWriteError,
        organization::{
            Organization, OrganizationId, events::CREATED_ORGANIZATION,
            repository::OrganizationWriteRepository,
        },
    },
};
use std::sync::Arc;

/// Encapsulates the business logic of creating a Organization
#[derive(Clone)]
pub struct CreateOrganizationUseCase {
    authorization_service: Arc<dyn AuthorizationService>,
    repository: Arc<dyn OrganizationWriteRepository>,
    event_publisher: Arc<dyn EventPublisher>,
}

impl CreateOrganizationUseCase {
    pub fn new(
        authorization_service: Arc<dyn AuthorizationService>,
        repository: Arc<dyn OrganizationWriteRepository>,
        event_emitter: Arc<dyn EventPublisher>,
    ) -> Self {
        Self {
            authorization_service,
            repository,
            event_publisher: event_emitter,
        }
    }
}

#[async_trait::async_trait]
impl UseCase for CreateOrganizationUseCase {
    type Request = CreateOrganization;
    type Response = Result<OrganizationId, CreateOrganizationError>;

    async fn handle(&self, request: CreateOrganization) -> Self::Response {
        self.authorization_service
            .require_realm_admin(&request)
            .map_err(CreateOrganizationError::Forbidden)?;

        let (organization, event) = Organization::create(
            request.aggregate_id().value(),
            request.name().to_owned(),
            request.display_name().to_owned(),
            request.attributes().clone(),
            0,
        )
        .map_err(CreateOrganizationError::Invariant)?;

        self.repository
            .create(&organization)
            .await
            .map_err(CreateOrganizationError::Database)?;

        self.event_publisher
            .publish(CREATED_ORGANIZATION, Arc::new(event));
        Ok(*organization.id())
    }
}

#[derive(Debug)]
pub enum CreateOrganizationError {
    Forbidden(ForbiddenError),
    Invariant(DomainError),
    Database(RepositoryWriteError),
}

#[cfg(test)]
mod tests {
    use kern::application::ids::AuthorizedParty;
    use kern::application::use_case::UseCase;
    use mockall::Sequence;
    use std::{collections::HashMap, sync::Arc};
    use uuid::Uuid;

    use crate::domain::authorization::authorized_scope::AuthorizedScope;
    use crate::{
        application::{
            MockTestEventPublisher,
            organization::{
                command_factory::OrganizationCommandFactory, create::CreateOrganizationUseCase,
            },
        },
        domain::{
            authorization::MockAuthorizationService,
            organization::repository::MockOrganizationWriteRepository,
        },
    };

    #[tokio::test]
    async fn given_a_command_when_processed_then_is_should_succeed() {
        let mut sequence = Sequence::new();
        let mut authorization_service = MockAuthorizationService::new();
        authorization_service
            .expect_require_realm_admin()
            .times(1)
            .in_sequence(&mut sequence)
            .returning(|_| Ok(()));

        let mut repository = MockOrganizationWriteRepository::new();
        repository
            .expect_create()
            .times(1)
            .in_sequence(&mut sequence)
            .returning(|_| Result::Ok(()));

        let mut event_emitter = MockTestEventPublisher::new();
        event_emitter
            .expect_publish()
            .times(1)
            .in_sequence(&mut sequence)
            .returning(|_, _| ());

        let use_case = CreateOrganizationUseCase::new(
            Arc::new(authorization_service),
            Arc::new(repository),
            Arc::new(event_emitter),
        );

        let command_factory = OrganizationCommandFactory::new(
            kern::application::environment::Environment::Development,
        );

        let authorized_scope = AuthorizedScope::RealmAdmin;
        let command = command_factory
            .create(
                Uuid::new_v4().to_string(),
                "organization-a".to_string(),
                "Organization A".to_string(),
                HashMap::default(),
                AuthorizedParty::new("test.client".to_string()),
                Uuid::new_v4().to_string(),
                authorized_scope,
            )
            .unwrap();
        let created_id = use_case.handle(command.clone()).await.unwrap();
        assert_eq!(command.aggregate_id().value(), created_id.value());
    }
}
