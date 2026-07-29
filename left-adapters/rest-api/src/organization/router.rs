use std::sync::Arc;

use auth_core::{
    application::organization::{
        command_factory::OrganizationCommandFactory, create::CreateOrganizationUseCase,
    },
    domain::{
        authorization::AuthorizationService, organization::repository::OrganizationWriteRepository,
    },
};
use axum::{Router, routing::post};
use kern::application::event::EventPublisher;

use crate::{
    authorization::jwt::JwtVerifier,
    organization::{CreateOrganizationState, OrganizationState, create},
};

pub fn create_organization_router(state: CreateOrganizationState) -> Router {
    Router::new()
        .route("/create", post(create))
        .with_state(state)
}

pub fn create_organization_state(
    authorization_service: Arc<dyn AuthorizationService>,
    jwt_verifier: Arc<dyn JwtVerifier>,
    event_emitter: Arc<dyn EventPublisher>,
    organization_command_factory: Arc<OrganizationCommandFactory>,
    organization_write_repository: Arc<dyn OrganizationWriteRepository>,
) -> OrganizationState {
    // Create the depeendencies for the Organization Resource
    let use_case = Arc::new(CreateOrganizationUseCase::new(
        authorization_service,
        organization_write_repository,
        event_emitter,
    ));
    let create_organization_state = CreateOrganizationState {
        factory: organization_command_factory,
        jwt_verifier,
        use_case,
    };
    OrganizationState {
        create: create_organization_state,
    }
}
