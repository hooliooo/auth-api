use std::{borrow::Cow, str::FromStr};

use uuid::{Uuid, Variant, Version};
use validator::ValidationError;

use crate::domain::organization::OrganizationId;

pub mod authorization;
pub mod exception;
pub mod organization;
pub mod state;
pub mod user;

pub trait OrganizationCapability {
    fn tenant_id(&self) -> Option<OrganizationId>;
}

fn validate_whitespace(string: &str) -> Result<(), ValidationError> {
    if string.is_empty() {
        return Err(ValidationError::new("whitespace").with_message(Cow::from("is blank")));
    }

    if string.trim().len() != string.len() {
        return Err(ValidationError::new("leading_or_trailing_whitespace")
            .with_message(Cow::from("has leading or trailing whitespace")));
    }

    Ok(())
}

/// Checks if the string slice is a valid UUIDv7. Returns an error if invalid
/// # Arguments
/// * `value` The string slice to be validated
pub fn validate_id(value: &str) -> Result<(), ValidationError> {
    match Uuid::from_str(value) {
        Ok(uuid) => {
            let is_valid = uuid.get_version() == Some(Version::SortRand)
                && uuid.get_variant() == Variant::RFC4122;
            if is_valid {
                Ok(())
            } else {
                Err(ValidationError::new("uuid").with_message(Cow::from("is not a uuid v7")))
            }
        }
        Err(_) => Err(ValidationError::new("uuid").with_message(Cow::from("is not a uuid"))),
    }
}
