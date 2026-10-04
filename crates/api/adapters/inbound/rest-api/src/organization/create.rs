//! `POST /organizations/create`: from JSON payload to `CreateOrganization` to response.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use auth_core::{
    application::{
        authorization::AuthorizedRequest,
        organization::{commands::CreateOrganization, create::CreateOrganizationError},
    },
    domain::organization::{INVALID_ORGANIZATION_ID_ERROR, OrganizationId},
};
use axum::{
    extract::{FromRef, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use kern::{
    application::use_case::UseCase,
    building_blocks::error::domain_error::DomainError,
    infrastructure::error::axum_extensions::{StatusCodeError, StatusCodeErrors},
};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    AppState,
    command::{Authorized, FromPayload},
    error::ApiError,
};

pub type CreateOrganizationApplicationService = dyn UseCase<
        Request = AuthorizedRequest<CreateOrganization>,
        Response = Result<OrganizationId, CreateOrganizationError>,
    > + Send
    + Sync;

#[derive(Clone)]
pub struct CreateOrganizationState {
    pub use_case: Arc<CreateOrganizationApplicationService>,
}

impl FromRef<AppState> for CreateOrganizationState {
    fn from_ref(input: &AppState) -> Self {
        input.organization.create.clone()
    }
}

/// Creates an Organization, answering with its path in the `Location` header.
#[utoipa::path(
    post,
    path = "/organizations/create",
    request_body = CreateOrganizationRequest,
    responses(
        (status = 204, description = "Organization created",
            headers(("Location" = String, description = "Path of the created organization"))),
        (status = 400, description = "Malformed JSON body", body = StatusCodeError),
        (status = 401, description = "Missing, invalid or unsupported bearer token", body = StatusCodeError),
        (status = 403, description = "Caller is not a realm admin", body = StatusCodeError),
        (status = 409, description = "An organization with this id or name already exists", body = StatusCodeError),
        (status = 415, description = "Body is not `application/json`", body = StatusCodeError),
        (status = 422, description = "Invalid organization data; several violations come as a list", body = StatusCodeErrors),
        (status = 500, description = "The organization could not be saved", body = StatusCodeError),
        (status = 503, description = "Tokens cannot be verified right now", body = StatusCodeError),
    )
)]
pub async fn handler(
    State(state): State<CreateOrganizationState>,
    Authorized(command): Authorized<CreateOrganization>,
) -> Result<Response, ApiError> {
    let created_id = state.use_case.handle(command).await?;
    // Relative, so it stays correct behind proxies whatever scheme and host the client used
    let location = format!("/organizations/{}", created_id.value());
    Ok((StatusCode::NO_CONTENT, [(header::LOCATION, location)]).into_response())
}

#[derive(Deserialize, ToSchema)]
pub struct CreateOrganizationRequest {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub is_enabled: bool,
    pub attributes: HashMap<String, HashSet<String>>,
}

impl TryFrom<CreateOrganizationRequest> for CreateOrganization {
    type Error = DomainError;

    fn try_from(value: CreateOrganizationRequest) -> Result<Self, Self::Error> {
        let Ok(id) = Uuid::try_from(value.id) else {
            return Err(DomainError::single(INVALID_ORGANIZATION_ID_ERROR));
        };

        Ok(CreateOrganization::new(
            id,
            value.name,
            value.display_name,
            value.description,
            value.is_enabled,
            value.attributes,
        ))
    }
}

impl FromPayload for CreateOrganization {
    type Payload = CreateOrganizationRequest;
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use auth_core::{
        application::organization::commands::CreateOrganization,
        domain::organization::INVALID_ORGANIZATION_ID_ERROR,
    };
    use uuid::Uuid;

    use super::CreateOrganizationRequest;

    fn request(id: String) -> CreateOrganizationRequest {
        CreateOrganizationRequest {
            id,
            name: "organization-a".to_string(),
            display_name: "Organization A".to_string(),
            description: "Some description".to_string(),
            is_enabled: true,
            attributes: HashMap::default(),
        }
    }

    #[test]
    fn given_a_valid_request_when_converted_then_it_should_keep_the_id() {
        let id = Uuid::now_v7();
        let command = CreateOrganization::try_from(request(id.to_string())).unwrap();
        assert_eq!(command.aggregate_id().value(), id);
    }

    #[test]
    fn given_a_non_uuid_id_when_converted_then_it_should_be_rejected() {
        let error = CreateOrganization::try_from(request("not-a-uuid".to_string())).unwrap_err();
        assert!(
            error
                .error_details()
                .any(|detail| *detail == INVALID_ORGANIZATION_ID_ERROR)
        );
    }

    #[test]
    fn given_duplicate_attribute_values_when_deserialized_then_they_should_collapse() {
        let json = format!(
            r#"{{"id":"{}","name":"a","display_name":"A","description":"","is_enabled":true,"attributes":{{"tier":["gold","gold"]}}}}"#,
            Uuid::now_v7()
        );
        let request: CreateOrganizationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(
            request.attributes["tier"],
            HashSet::from(["gold".to_string()])
        );
    }
}
