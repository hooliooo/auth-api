//! Turning an HTTP request into a core Command: the `Authorized` extractor and the traits a
//! Command implements to say which payload it is built from.

use auth_core::application::authorization::AuthorizedRequest;
use axum::{
    Json,
    extract::{
        FromRequest, Path, Request,
        rejection::{JsonRejection, PathRejection},
    },
};
use serde::de::DeserializeOwned;

use crate::{
    auth::{Authenticated, JwtVerifierState, authz_context},
    error::{ApiError, IntoApiError},
};

/// Names the HTTP payload a Command is built from. The validation itself is `TryFrom`.
pub trait FromPayload: TryFrom<Self::Payload> {
    type Payload: HttpPayload;
}

/// Where a payload comes from in the request: the route's path parameters and the JSON body.
/// Every JSON body type is a payload without path parameters; use [`WithPath`] when the
/// Command also needs the path, e.g. the `{id}` of `PUT /organizations/{id}`.
pub trait HttpPayload: Sized {
    type Path: DeserializeOwned + Send;
    type Body: DeserializeOwned + Send;

    fn from_parts(path: Self::Path, body: Self::Body) -> Self;
}

impl<T: DeserializeOwned + Send> HttpPayload for T {
    type Path = ();
    type Body = T;

    fn from_parts(_path: (), body: T) -> Self {
        body
    }
}

/// A payload made of the route's path parameters and a JSON body.
pub struct WithPath<P, B> {
    pub path: P,
    pub body: B,
}

impl<P, B> HttpPayload for WithPath<P, B>
where
    P: DeserializeOwned + Send,
    B: DeserializeOwned + Send,
{
    type Path = P;
    type Body = B;

    fn from_parts(path: P, body: B) -> Self {
        Self { path, body }
    }
}

/// An authenticated payload, validated into Command `C`.
/// Must be the last handler argument (it consumes the body).
pub struct Authorized<C>(pub AuthorizedRequest<C>);

impl<S, C> FromRequest<S> for Authorized<C>
where
    S: JwtVerifierState + Send + Sync,
    C: FromPayload,
    C::Error: IntoApiError,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        type PathOf<C> = <<C as FromPayload>::Payload as HttpPayload>::Path;
        type BodyOf<C> = <<C as FromPayload>::Payload as HttpPayload>::Body;

        // Authentication runs first, so an unauthenticated request never has its body read.
        // Path and body failures are caught as values to render them as `StatusCodeError`.
        let (Authenticated(claims), path, body) = <(
            Authenticated,
            Result<Path<PathOf<C>>, PathRejection>,
            Result<Json<BodyOf<C>>, JsonRejection>,
        )>::from_request(req, state)
        .await
        .map_err(ApiError::from_response)?;

        let Path(path) = path?;
        let Json(body) = body?;
        let context = authz_context(claims)?;
        let command = C::try_from(C::Payload::from_parts(path, body))?;
        Ok(Self(AuthorizedRequest::new(context, command)))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use auth_core::application::authentication::{Claims, JwtVerificationError, JwtVerifier};
    use auth_core::application::authorization::authorized_scope::AuthorizedScope;
    use axum::{
        Router,
        body::Body,
        extract::Request,
        http::{Method, StatusCode, header},
        routing::put,
    };
    use kern::building_blocks::error::domain_error::DomainError;
    use serde::Deserialize;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::{Authorized, FromPayload, WithPath};
    use crate::auth::JwtVerifierState;

    /// A Command that needs both the path and the body, as an update would.
    struct Rename {
        id: Uuid,
        name: String,
    }

    #[derive(Deserialize)]
    struct RenameRequest {
        name: String,
    }

    impl TryFrom<WithPath<Uuid, RenameRequest>> for Rename {
        type Error = DomainError;

        fn try_from(payload: WithPath<Uuid, RenameRequest>) -> Result<Self, Self::Error> {
            Ok(Self {
                id: payload.path,
                name: payload.body.name,
            })
        }
    }

    impl FromPayload for Rename {
        type Payload = WithPath<Uuid, RenameRequest>;
    }

    struct AcceptAll;

    #[async_trait::async_trait]
    impl JwtVerifier for AcceptAll {
        async fn verify(&self, _raw_token: &str) -> Result<Claims, JwtVerificationError> {
            Ok(Claims {
                client_id: "test.client".to_string(),
                user_id: Uuid::now_v7().to_string(),
                authorized_scope: AuthorizedScope::SuperAdmin,
            })
        }
    }

    #[derive(Clone)]
    struct TestState;

    impl JwtVerifierState for TestState {
        fn jwt_verifier(&self) -> Arc<dyn JwtVerifier> {
            Arc::new(AcceptAll)
        }
    }

    async fn rename(Authorized(request): Authorized<Rename>) -> String {
        let command = request.payload();
        format!("{} {}", command.id, command.name)
    }

    fn put_rename(id: &str, body: &str) -> Request {
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/{id}"))
            .header(header::AUTHORIZATION, "Bearer test")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap()
    }

    fn router() -> Router {
        Router::new()
            .route("/{id}", put(rename))
            .with_state(TestState)
    }

    #[tokio::test]
    async fn given_a_path_and_body_when_extracted_then_the_command_should_have_both() {
        let id = Uuid::now_v7();
        let response = router()
            .oneshot(put_rename(&id.to_string(), r#"{"name":"renamed"}"#))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body, format!("{id} renamed"));
    }

    #[tokio::test]
    async fn given_an_invalid_path_when_extracted_then_it_should_be_a_json_error() {
        let response = router()
            .oneshot(put_rename("not-a-uuid", r#"{"name":"renamed"}"#))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    }
}
