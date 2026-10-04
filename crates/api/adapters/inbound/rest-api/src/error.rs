//! One JSON error shape, [`StatusCodeError`], for every failure the API returns. Handlers
//! return `Result<_, ApiError>` and use `?`.
//!
//! Every translation of an error into a response lives in this module:
//! - `shared`: the core and axum errors every resource can hit
//! - `authentication`: rejected bearer tokens
//! - one file per resource, e.g. `organization`, for its use cases' error enums, which
//!   delegate to the shared translations so equal failures get equal responses

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kern::infrastructure::error::axum_extensions::StatusCodeError;

pub mod authentication;
pub mod organization;
pub mod shared;

/// An error response, already rendered as [`StatusCodeError`] JSON.
/// Boxed so `Result<_, ApiError>` stays pointer-sized; the allocation only happens on failure.
pub struct ApiError(Box<Response>);

impl ApiError {
    pub fn new(status: StatusCode, error_key: &str, description: impl Into<String>) -> Self {
        let body = StatusCodeError::new(error_key.to_owned(), description.into());
        Self::from_response((status, Json(body)).into_response())
    }

    /// Wraps a response some other extractor already rendered as an error.
    pub(crate) fn from_response(response: Response) -> Self {
        Self(Box::new(response))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        *self.0
    }
}

/// An error that knows its HTTP representation. `?` converts any of them in handlers.
pub trait IntoApiError {
    fn into_api_error(self) -> ApiError;
}

impl<E: IntoApiError> From<E> for ApiError {
    fn from(error: E) -> Self {
        error.into_api_error()
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use axum::{body::to_bytes, http::StatusCode, response::IntoResponse};
    use kern::infrastructure::error::axum_extensions::StatusCodeError;

    use super::IntoApiError;

    /// Renders `error` the way a handler would and reads back its status and JSON body.
    pub(crate) async fn render(error: impl IntoApiError) -> (StatusCode, StatusCodeError) {
        let response = error.into_api_error().into_response();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }
}
