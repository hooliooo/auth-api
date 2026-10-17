use kern::{
    application::{
        error::forbidden_error::ForbiddenError, event::EventPublisher, use_case::UseCase,
    },
    building_blocks::domain_event::DomainEvent,
    building_blocks::entity::Entity,
    building_blocks::error::domain_error::DomainError,
};

use crate::{
    application::{
        authorization::{AuthorizationService, AuthorizedRequest},
        organization::commands::CreateOrganization,
    },
    domain::{
        error::RepositoryWriteError,
        organization::{Organization, OrganizationId, repository::OrganizationWriteRepository},
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
    type Request = AuthorizedRequest<CreateOrganization>;
    type Response = Result<OrganizationId, CreateOrganizationError>;

    async fn handle(&self, request: AuthorizedRequest<CreateOrganization>) -> Self::Response {
        let (context, command) = request.into_parts();
        self.authorization_service
            .require_realm_admin(&context)
            .map_err(CreateOrganizationError::Forbidden)?;

        let (aggregate_id, name, display_name, description, is_enabled, attributes) =
            command.into_parts();

        let (organization, event) = Organization::create(
            aggregate_id,
            name,
            display_name,
            description,
            is_enabled,
            attributes,
            0,
        )
        .map_err(CreateOrganizationError::Invariant)?;

        // The event is handed to the repository so it lands in the outbox inside the same
        // transaction as the aggregate. The publish below stays for in-process subscribers;
        // the outbox row is what makes delivery survive a crash here.
        self.repository
            .create(&organization, &event)
            .await
            .map_err(CreateOrganizationError::Database)?;

        let event_type = event.event_type();
        self.event_publisher.publish(event_type, Arc::new(event));
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
    use std::{collections::HashMap, sync::Arc};
    use uuid::Uuid;

    use crate::{
        application::{
            authorization::{
                AuthAPIAuthorizationService, AuthorizedRequest, AuthzContext,
                authorized_scope::AuthorizedScope,
            },
            organization::{
                commands::CreateOrganization,
                create::{CreateOrganizationError, CreateOrganizationUseCase},
            },
        },
        domain::{error::RepositoryWriteError, organization::OrganizationId},
        test_support::{InMemoryOrganizationWriteRepository, RecordingEventPublisher},
    };

    struct Fixture {
        use_case: CreateOrganizationUseCase,
        repository: Arc<InMemoryOrganizationWriteRepository>,
        publisher: Arc<RecordingEventPublisher>,
    }

    fn fixture(repository: InMemoryOrganizationWriteRepository) -> Fixture {
        let repository = Arc::new(repository);
        let publisher = Arc::new(RecordingEventPublisher::default());
        let use_case = CreateOrganizationUseCase::new(
            Arc::new(AuthAPIAuthorizationService),
            repository.clone(),
            publisher.clone(),
        );
        Fixture {
            use_case,
            repository,
            publisher,
        }
    }

    fn request(scope: AuthorizedScope, name: &str) -> AuthorizedRequest<CreateOrganization> {
        AuthorizedRequest::new(
            AuthzContext::new(
                Uuid::now_v7(),
                Uuid::now_v7(),
                AuthorizedParty::new("test.client".to_string()),
                scope,
            ),
            CreateOrganization::new(
                Uuid::now_v7(),
                name.to_string(),
                "Organization A".to_string(),
                "Some description".to_string(),
                true,
                HashMap::default(),
            ),
        )
    }

    #[tokio::test]
    async fn given_a_realm_admin_when_created_then_it_should_store_and_publish_the_organization() {
        let Fixture {
            use_case,
            repository,
            publisher,
        } = fixture(InMemoryOrganizationWriteRepository::default());
        let request = request(AuthorizedScope::SuperAdmin, "organization-a");
        let aggregate_id = *request.payload().aggregate_id();

        let created_id = use_case.handle(request).await.unwrap();

        assert_eq!(aggregate_id, created_id);
        assert!(repository.contains(&created_id));
        let published = publisher.published();
        assert_eq!(published.len(), 1);
        assert_eq!(
            published[0]
                .1
                .aggregate_id()
                .downcast_ref::<OrganizationId>(),
            Some(&created_id)
        );
    }

    #[tokio::test]
    async fn given_a_non_realm_admin_when_created_then_it_should_be_forbidden() {
        let Fixture {
            use_case,
            repository,
            publisher,
        } = fixture(InMemoryOrganizationWriteRepository::default());

        let error = use_case
            .handle(request(
                AuthorizedScope::OrganizationAdmin,
                "organization-a",
            ))
            .await
            .unwrap_err();

        assert!(matches!(error, CreateOrganizationError::Forbidden(_)));
        assert!(repository.is_empty());
        assert!(publisher.published().is_empty());
    }

    #[tokio::test]
    async fn given_an_invalid_name_when_created_then_it_should_break_an_invariant() {
        let Fixture {
            use_case,
            repository,
            publisher,
        } = fixture(InMemoryOrganizationWriteRepository::default());

        let error = use_case
            .handle(request(AuthorizedScope::SuperAdmin, "a"))
            .await
            .unwrap_err();

        assert!(matches!(error, CreateOrganizationError::Invariant(_)));
        assert!(repository.is_empty());
        assert!(publisher.published().is_empty());
    }

    #[tokio::test]
    async fn given_a_taken_name_when_created_then_it_should_publish_only_the_first() {
        let Fixture {
            use_case,
            repository,
            publisher,
        } = fixture(InMemoryOrganizationWriteRepository::default());
        use_case
            .handle(request(AuthorizedScope::SuperAdmin, "organization-a"))
            .await
            .unwrap();

        let error = use_case
            .handle(request(AuthorizedScope::SuperAdmin, "organization-a"))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            CreateOrganizationError::Database(RepositoryWriteError::AlreadyExists {
                field: "name",
                ..
            })
        ));
        assert_eq!(repository.len(), 1);
        assert_eq!(publisher.published().len(), 1);
    }

    #[tokio::test]
    async fn given_a_repository_failure_when_created_then_it_should_not_publish() {
        let Fixture {
            use_case,
            publisher,
            ..
        } = fixture(InMemoryOrganizationWriteRepository::failing(
            "connection refused",
        ));

        let error = use_case
            .handle(request(AuthorizedScope::SuperAdmin, "organization-a"))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            CreateOrganizationError::Database(RepositoryWriteError::Failure(_))
        ));
        assert!(publisher.published().is_empty());
    }
}
