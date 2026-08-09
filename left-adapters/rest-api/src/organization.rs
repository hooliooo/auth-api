use auth_core::{
    application::organization::{
        command_factory::OrganizationCommandFactory, commands::CreateOrganization,
        create::CreateOrganizationError,
    },
    domain::{exception::RepositoryWriteError, organization::OrganizationId},
};
use axum_extra::{TypedHeader, headers::Host};
use kern::{
    application::{ids::AuthorizedParty, use_case::UseCase},
    infrastructure::error::axum_extensions::StatusCodeError,
};
use std::sync::Arc;

use axum::{
    Json,
    extract::{FromRef, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use tracing::debug;

use crate::{
    AppState,
    authorization::jwt::{Authenticated, JwtVerifier, JwtVerifierState},
    organization::request::CreateOrganizationRequest,
};

pub mod request;
pub mod router;

#[derive(Clone)]
pub struct OrganizationState {
    pub create: CreateOrganizationState,
}

impl FromRef<AppState> for OrganizationState {
    fn from_ref(input: &AppState) -> Self {
        input.organization.clone()
    }
}

pub type CreateOrganizationApplicationService = dyn UseCase<
        Request = CreateOrganization,
        Response = Result<OrganizationId, CreateOrganizationError>,
    > + Send
    + Sync;

#[derive(Clone)]
pub struct CreateOrganizationState {
    pub factory: Arc<OrganizationCommandFactory>,
    pub jwt_verifier: Arc<dyn JwtVerifier>,
    pub use_case: Arc<CreateOrganizationApplicationService>,
}

impl JwtVerifierState for CreateOrganizationState {
    fn jwt_verifier(&self) -> Arc<dyn JwtVerifier> {
        self.jwt_verifier.clone()
    }
}

impl FromRef<AppState> for CreateOrganizationState {
    fn from_ref(input: &AppState) -> Self {
        input.organization.create.clone()
    }
}

/// Create Organization Handler
/// # Arguments
/// * `claims` - The JWT claims from the request
/// * `host`   - The host of the request
/// * `state`  - The UseCase that will execute the business logic on the request
/// * `body`   - The body of the request
///
#[utoipa::path(
    post,
    path = "organizations/create",
    request_body = CreateOrganizationRequest,
    responses(
        (status = 204, description = "Organization created successfully"),
        (status = 422, description = "User input related error", body = StatusCodeError)
    )
)]
pub async fn create(
    Authenticated(claims): Authenticated,
    host: Option<TypedHeader<Host>>,
    State(state): State<CreateOrganizationState>,
    Json(body): Json<CreateOrganizationRequest>,
) -> Response {
    let result = state.factory.create(
        body.id,
        body.name,
        body.display_name,
        body.description,
        body.is_enabled,
        body.attributes,
        AuthorizedParty::new(claims.client_id),
        claims.user_id,
        claims.authorized_scope,
    );

    let command: CreateOrganization = match result {
        Ok(command) => command,
        Err(error) => return error.into_response(),
    };

    match state.use_case.handle(command).await {
        Ok(created_id) => {
            let mut response = StatusCode::NO_CONTENT.into_response();

            let uri = match host {
                Some(TypedHeader(host)) => {
                    format!(
                        "{}:{}/organizations/{}",
                        host.hostname(),
                        host.port().unwrap(),
                        created_id.value()
                    )
                }
                None => {
                    format!("/organizations/{}", created_id.value())
                }
            };

            response
                .headers_mut()
                .insert(header::LOCATION, HeaderValue::from_str(&uri).unwrap());
            response
        }
        Err(err) => match err {
            CreateOrganizationError::Forbidden(err) => {
                debug!("Not allowed to create organization");
                err.into_response()
            }
            CreateOrganizationError::Invariant(err) => {
                debug!("User input error");
                err.into_response()
            }
            CreateOrganizationError::Database(err) => match err {
                RepositoryWriteError::AlreadyExists(entity_name, id) => {
                    debug!("Organization already exists with ID");
                    (
                        StatusCode::CONFLICT,
                        format!("{} with id: '{}'", entity_name, id),
                    )
                        .into_response()
                }
                RepositoryWriteError::Failure(message) => {
                    debug!("Database Failure: {:?}", message.clone());
                    (
                        StatusCode::CONFLICT,
                        format!("Unable to save entity: {}", message),
                    )
                        .into_response()
                }
            },
        },
    }
}
