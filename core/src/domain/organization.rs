use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    marker::PhantomData,
    sync::LazyLock,
};

use chrono::Utc;
use kern::{
    Aggregate,
    building_blocks::entity::Entity,
    building_blocks::error::{domain_error::DomainError, error_detail::ErrorDetail},
    validator_extensions::ResultValidation,
};
use regex::Regex;
use uuid::Uuid;
use validator::{Validate, ValidationError};

use crate::domain::{
    organization::events::CreatedOrganization, state::Create, validate_whitespace,
};

pub mod events;
pub mod repository;

pub const INVALID_ORGANIZATION_ID_ERROR: ErrorDetail = ErrorDetail::new_const(
    "error.organization.invalid-id",
    "User inputted id is not a valid UUID",
);

/// A Organization represents an isolated environment where administrators can assign
/// and manage user authorizations. Any JWTs created scoped to a Organization are exclusive
/// to that Organization and cannot be used across other Organizations.
#[derive(Aggregate, Debug, Validate)]
pub struct Organization<State> {
    /// The unique identifier of the Organization
    #[entity_id]
    #[generate_id(Uuid)]
    id: OrganizationId,
    /// The name of the Organization
    #[validate(
        length(
            min = 3,
            max = 100,
            message = "must be at least 3 chars but 100 chars or less"
        ),
        custom(function = "validate_whitespace"),
        custom(function = "validate_name")
    )]
    #[field]
    name: String,
    #[validate(
        length(
            min = 3,
            max = 100,
            message = "must be at least 3 chars but 100 chars or less"
        ),
        custom(function = "validate_whitespace")
    )]
    #[field]
    /// The human-readable name of the Organization
    display_name: String,
    /// Custom key-value pairs that are specific to this Organization
    #[field]
    attributes: HashMap<String, HashSet<String>>,
    /// The current version of the Organization. This value is incremented for every update to the Organization
    version: u32,
    _marker: PhantomData<State>,
}

impl<State> Organization<State> {
    /// Instantiates a Organization
    /// # Arguments
    /// * `id`           - The id of the Organization
    /// * `name`         - The unique name of the Organization
    /// * `display_name` - The human-readable name of the Organization
    /// * `attributes`   - The attributes of the Organization
    /// * `version`      - The version of the Organization
    /// # Return
    /// A `Result<Self, DomainError>`
    pub fn try_new(
        id: Uuid,
        name: String,
        display_name: String,
        attributes: HashMap<String, HashSet<String>>,
        version: u32,
    ) -> Result<Self, DomainError> {
        let model = Self {
            id: OrganizationId::new(id),
            name,
            display_name,
            attributes,
            version,
            _marker: PhantomData,
        };

        model.validate().map(|_| model).to_domain_error()
    }
}

impl Organization<Create> {
    /// Creates a `CreatedOrganization` domain event
    /// # Arguments
    /// * `request` - The command that created the Organization
    /// # Return
    /// A `CreatedOrganization` domain event
    pub fn create(
        id: Uuid,
        name: String,
        display_name: String,
        attributes: HashMap<String, HashSet<String>>,
        version: u32,
    ) -> Result<(Self, CreatedOrganization), DomainError> {
        let aggregate =
            Organization::<Create>::try_new(id, name, display_name, attributes, version)?;

        let event = CreatedOrganization::new(
            *aggregate.id(),
            aggregate.version,
            aggregate.name.clone(),
            aggregate.display_name.clone(),
            aggregate.attributes().clone(),
            Utc::now(),
        );
        Ok((aggregate, event))
    }
}

static NAME_DNS_COMPATIBILITY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9-]+$").unwrap());

fn validate_name(string: &str) -> Result<(), ValidationError> {
    if !NAME_DNS_COMPATIBILITY_REGEX.is_match(string) {
        return Err(ValidationError::new("incompatible_dns_name")
            .with_message(Cow::from("is not dns compatible")));
    };
    Ok(())
}

#[cfg(test)]
mod tests {

    mod try_new {
        use std::collections::HashMap;

        use kern::building_blocks::error::{domain_error::DomainError, error_detail::ErrorDetail};
        use uuid::Uuid;

        use crate::domain::{organization::Organization, state::Create};

        #[test]
        fn given_a_name_is_too_long_when_try_new_is_called_then_an_error_should_be_returned() {
            let result: Result<Organization<Create>, DomainError> = Organization::try_new(
                Uuid::new_v4(),
                "x".repeat(101),
                "Some Display Name".to_string(),
                HashMap::default(),
                0,
            );

            assert!(result.is_err());
            let error = result.err().unwrap();
            assert_eq!(
                error.error_details().collect::<Vec<&ErrorDetail>>().len(),
                1
            );
            let detail = error.error_details().next().unwrap();
            assert_eq!(detail.key(), "error.organization.invalid-name");
            assert_eq!(
                detail.message(),
                "'name' must be at least 3 chars but 100 chars or less"
            );
        }

        #[test]
        fn given_a_name_is_blank_when_try_new_is_called_then_an_error_should_be_returned() {
            let result: Result<Organization<Create>, DomainError> = Organization::try_new(
                Uuid::new_v4(),
                "   ".to_string(),
                "Some Display Name".to_string(),
                HashMap::default(),
                0,
            );

            assert!(result.is_err());
            let error = result.err().unwrap();
            assert_eq!(
                error.error_details().collect::<Vec<&ErrorDetail>>().len(),
                1
            );
            let detail = error.error_details().next().unwrap();
            assert_eq!(detail.key(), "error.organization.invalid-name");
            assert_eq!(
                detail.message(),
                "'name' has leading or trailing whitespace"
            );
        }

        #[test]
        fn given_a_name_has_whitespace_when_try_new_is_called_then_an_error_should_be_returned() {
            let result: Result<Organization<Create>, DomainError> = Organization::try_new(
                Uuid::new_v4(),
                "  a".to_string(),
                "Some Display Name".to_string(),
                HashMap::default(),
                0,
            );

            assert!(result.is_err());
            let error = result.err().unwrap();
            assert_eq!(
                error.error_details().collect::<Vec<&ErrorDetail>>().len(),
                1
            );
            let detail = error.error_details().next().unwrap();
            assert_eq!(detail.key(), "error.organization.invalid-name");
            assert_eq!(
                detail.message(),
                "'name' has leading or trailing whitespace"
            );

            let result: Result<Organization<Create>, DomainError> = Organization::try_new(
                Uuid::new_v4(),
                "a   ".to_string(),
                "Some Display Name".to_string(),
                HashMap::default(),
                0,
            );

            assert!(result.is_err());
            let error = result.err().unwrap();
            assert_eq!(
                error.error_details().collect::<Vec<&ErrorDetail>>().len(),
                1
            );
            let detail = error.error_details().next().unwrap();
            assert_eq!(detail.key(), "error.organization.invalid-name");
            assert_eq!(
                detail.message(),
                "'name' has leading or trailing whitespace"
            );
        }

        #[test]
        fn given_a_name_is_dns_incompatible_when_try_new_is_called_then_an_error_should_be_returned()
         {
            let result: Result<Organization<Create>, DomainError> = Organization::try_new(
                Uuid::new_v4(),
                "organization_a".to_string(),
                "Some Display Name".to_string(),
                HashMap::default(),
                0,
            );

            assert!(result.is_err());
            let error = result.err().unwrap();
            assert_eq!(
                error.error_details().collect::<Vec<&ErrorDetail>>().len(),
                1
            );
            let detail = error.error_details().next().unwrap();
            assert_eq!(detail.key(), "error.organization.invalid-name");
            assert_eq!(detail.message(), "'name' is not dns compatible");
        }

        #[test]
        fn given_a_display_name_is_too_long_when_try_new_is_called_then_an_error_should_be_returned()
         {
            let result: Result<Organization<Create>, DomainError> = Organization::try_new(
                Uuid::new_v4(),
                "organization-a".to_string(),
                "x".repeat(101),
                HashMap::default(),
                0,
            );

            assert!(result.is_err());
            let error = result.err().unwrap();
            assert_eq!(
                error.error_details().collect::<Vec<&ErrorDetail>>().len(),
                1
            );
            let detail = error.error_details().next().unwrap();
            assert_eq!(detail.key(), "error.organization.invalid-display-name");
            assert_eq!(
                detail.message(),
                "'display_name' must be at least 3 chars but 100 chars or less"
            );
        }

        #[test]
        fn given_a_display_name_is_blank_when_try_new_is_called_then_an_error_should_be_returned() {
            let result: Result<Organization<Create>, DomainError> = Organization::try_new(
                Uuid::new_v4(),
                "organization-a".to_string(),
                "   ".to_string(),
                HashMap::default(),
                0,
            );

            assert!(result.is_err());
            let error = result.err().unwrap();
            assert_eq!(
                error.error_details().collect::<Vec<&ErrorDetail>>().len(),
                1
            );
            let detail = error.error_details().next().unwrap();
            assert_eq!(detail.key(), "error.organization.invalid-display-name");
            assert_eq!(
                detail.message(),
                "'display_name' has leading or trailing whitespace"
            );
        }

        #[test]
        fn given_a_display_name_has_whitespace_when_try_new_is_called_then_an_error_should_be_returned()
         {
            let result: Result<Organization<Create>, DomainError> = Organization::try_new(
                Uuid::new_v4(),
                "organization-a".to_string(),
                "  a".to_string(),
                HashMap::default(),
                0,
            );

            assert!(result.is_err());
            let error = result.err().unwrap();
            assert_eq!(
                error.error_details().collect::<Vec<&ErrorDetail>>().len(),
                1
            );
            let detail = error.error_details().next().unwrap();
            assert_eq!(detail.key(), "error.organization.invalid-display-name");
            assert_eq!(
                detail.message(),
                "'display_name' has leading or trailing whitespace"
            );

            let result: Result<Organization<Create>, DomainError> = Organization::try_new(
                Uuid::new_v4(),
                "organization-a".to_string(),
                "a   ".to_string(),
                HashMap::default(),
                0,
            );

            assert!(result.is_err());
            let error = result.err().unwrap();
            assert_eq!(
                error.error_details().collect::<Vec<&ErrorDetail>>().len(),
                1
            );
            let detail = error.error_details().next().unwrap();
            assert_eq!(detail.key(), "error.organization.invalid-display-name");
            assert_eq!(
                detail.message(),
                "'display_name' has leading or trailing whitespace"
            );
        }

        #[test]
        fn given_valid_inputs_when_try_new_is_called_then_it_should_be_a_success() {
            let result: Result<Organization<Create>, DomainError> = Organization::try_new(
                Uuid::new_v4(),
                "organization-a".to_string(),
                "Organization A".to_string(),
                HashMap::default(),
                0,
            );
            assert!(result.is_ok());
        }
    }
}
