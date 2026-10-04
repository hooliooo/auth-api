//! The Organization resource: its routes, and the state its endpoints share. Each endpoint,
//! from payload to response, is one file in this module.

use std::sync::Arc;

use auth_core::{
    application::{
        authorization::AuthorizationService, organization::create::CreateOrganizationUseCase,
    },
    domain::organization::repository::OrganizationWriteRepository,
};
use axum::{Router, extract::FromRef, routing::post};
use kern::application::event::EventPublisher;

use crate::AppState;

pub mod create;

/// The Organization routes, nested under `/organizations`.
pub fn router() -> Router<AppState> {
    Router::new().route("/create", post(create::handler))
}

#[derive(Clone)]
pub struct OrganizationState {
    pub create: create::CreateOrganizationState,
}

impl OrganizationState {
    /// Builds the Organization use cases from the dependencies they need.
    pub fn new(
        authorization_service: Arc<dyn AuthorizationService>,
        event_emitter: Arc<dyn EventPublisher>,
        organization_write_repository: Arc<dyn OrganizationWriteRepository>,
    ) -> Self {
        let use_case = Arc::new(CreateOrganizationUseCase::new(
            authorization_service,
            organization_write_repository,
            event_emitter,
        ));
        Self {
            create: create::CreateOrganizationState { use_case },
        }
    }
}

impl FromRef<AppState> for OrganizationState {
    fn from_ref(input: &AppState) -> Self {
        input.organization.clone()
    }
}
