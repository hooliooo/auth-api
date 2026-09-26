//! Translations for the errors any resource can hit: the core's building blocks and axum's
//! request rejections.

use auth_core::domain::exception::RepositoryWriteError;
use axum::{
    extract::rejection::{JsonRejection, PathRejection},
    http::StatusCode,
    response::IntoResponse,
};
use kern::{
    application::error::forbidden_error::ForbiddenError,
    building_blocks::error::domain_error::DomainError,
};

use super::{ApiError, IntoApiError};

impl IntoApiError for DomainError {
    fn into_api_error(self) -> ApiError {
        ApiError::from_response(self.into_response())
    }
}

impl IntoApiError for ForbiddenError {
    fn into_api_error(self) -> ApiError {
        ApiError::from_response(self.into_response())
    }
}

impl IntoApiError for RepositoryWriteError {
    fn into_api_error(self) -> ApiError {
        match self {
            Self::AlreadyExists {
                ref entity, field, ..
            } => ApiError::new(
                StatusCode::CONFLICT,
                &format!("error.{entity}.{field}-already-exists"),
                self.to_string(),
            ),
            Self::Failure(message) => {
                // The message carries database internals, so it is logged, not returned
                tracing::error!(%message, "Repository failure");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "error.repository.failure",
                    "Unable to save entity",
                )
            }
        }
    }
}

impl IntoApiError for JsonRejection {
    fn into_api_error(self) -> ApiError {
        ApiError::new(
            self.status(),
            "error.request.invalid-body",
            self.body_text(),
        )
    }
}

impl IntoApiError for PathRejection {
    fn into_api_error(self) -> ApiError {
        ApiError::new(
            self.status(),
            "error.request.invalid-path",
            self.body_text(),
        )
    }
}

#[cfg(test)]
mod tests {
    use auth_core::domain::exception::RepositoryWriteError;
    use axum::http::StatusCode;

    use crate::error::test_support::render;

    #[tokio::test]
    async fn given_a_taken_name_when_rendered_then_it_should_name_the_field() {
        let (status, body) = render(RepositoryWriteError::AlreadyExists {
            entity: "organization".to_string(),
            field: "name",
            value: "organization-a".to_string(),
        })
        .await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body.error_key, "error.organization.name-already-exists");
    }

    #[tokio::test]
    async fn given_a_repository_failure_when_rendered_then_it_should_hide_the_details() {
        let (status, body) = render(RepositoryWriteError::Failure(
            "connection refused: 10.0.0.5".into(),
        ))
        .await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body.description.contains("10.0.0.5"));
    }
}
