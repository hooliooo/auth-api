//! Translations for the Organization use cases' errors. Each delegates to [`super::shared`].

use auth_core::application::organization::create::CreateOrganizationError;

use super::{ApiError, IntoApiError};

impl IntoApiError for CreateOrganizationError {
    fn into_api_error(self) -> ApiError {
        match self {
            Self::Forbidden(error) => error.into_api_error(),
            Self::Invariant(error) => error.into_api_error(),
            Self::Database(error) => error.into_api_error(),
        }
    }
}
