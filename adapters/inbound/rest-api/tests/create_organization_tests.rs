use std::sync::Arc;

use auth_core::application::authentication::{
    Claims, ClaimsExtractor, JwtVerificationError, JwtVerifier,
};
use auth_core::{
    application::{
        authorization::{AuthorizedRequest, authorized_scope::AuthorizedScope},
        organization::{commands::CreateOrganization, create::CreateOrganizationError},
    },
    domain::{exception::RepositoryWriteError, organization::OrganizationId},
};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http,
};
use kern::{
    application::use_case::UseCase, infrastructure::error::axum_extensions::StatusCodeError,
};
use mockall::mock;
use reqwest::StatusCode;
use rest_api::{
    AppState,
    organization::{
        OrganizationState,
        create::{CreateOrganizationApplicationService, CreateOrganizationState},
    },
};
use serde_json::from_slice;
use tower::ServiceExt;
use uuid::Uuid;

use crate::common::{TEST_HTTP_CLIENT, TestEnv, load_env_and_extract_access_token};

mod common;

fn setup_state(created_id: Uuid) -> Router {
    setup_state_returning(move || Ok(OrganizationId::new(created_id)))
}

fn setup_state_returning(
    mut result: impl FnMut() -> Result<OrganizationId, CreateOrganizationError> + Send + 'static,
) -> Router {
    let mut use_case = MockTestCreateOrganizationUseCase::new();
    use_case.expect_handle().returning(move |_req| result());
    let mut jwt = MockJWT::new();
    jwt.expect_extract().returning(|| {
        let authorized_scope = AuthorizedScope::SuperAdmin;
        Ok(Claims {
            client_id: Uuid::new_v4().to_string(),
            user_id: Uuid::new_v4().to_string(),
            authorized_scope,
        })
    });

    let mut jwt_verifier = MockTestJwtVerifier::new();
    jwt_verifier
        .expect_verify()
        .return_once(|_req| Ok(Box::new(jwt)));

    let organization = OrganizationState {
        create: CreateOrganizationState {
            use_case: Arc::new(use_case) as Arc<CreateOrganizationApplicationService>,
        },
    };

    rest_api::organization::router().with_state(AppState::new(Arc::new(jwt_verifier), organization))
}

mock! {
    pub TestCreateOrganizationUseCase {}

    #[async_trait::async_trait]
    impl UseCase for TestCreateOrganizationUseCase {
        type Request = AuthorizedRequest<CreateOrganization>;
        type Response = Result<OrganizationId, CreateOrganizationError>;

        async fn handle(&self, request: AuthorizedRequest<CreateOrganization>) -> Result<OrganizationId, CreateOrganizationError>;
    }
}

mock! {
    pub TestJwtVerifier {}

    #[async_trait::async_trait]
    impl JwtVerifier for TestJwtVerifier {
        async fn verify(&self, raw_token: &str) -> Result<Box<dyn ClaimsExtractor>, JwtVerificationError>;
    }
}

mock! {
    pub JWT {}

    impl ClaimsExtractor for JWT {
        fn extract(self: Box<Self>) -> Result<Claims, JwtVerificationError>;
    }
}

#[tokio::test]
async fn given_a_create_organization_request_with_an_invalid_id_when_sent_then_it_should_fail() {
    let router = setup_state(Uuid::new_v4());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/create")
                .method(http::Method::POST)
                .header(http::header::AUTHORIZATION, "Bearer test")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::new(
                    r###"
                    {
                        "id": "123",
                        "name": "Test",
                        "display_name": "Test",
                        "description": "Test",
                        "is_enabled": true,
                        "attributes": {},
                        "domain": null
                    }
                    "###
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    // let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

    // assert!(body_str.is_empty(), "Expected empty body, got: {body_str}");

    assert!(response.status().is_client_error());
    assert_eq!(response.status().as_u16(), 422);

    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: StatusCodeError = from_slice(&body_bytes).unwrap();
    assert_eq!(json.error_key, "error.organization.invalid-id")
}

#[tokio::test]
async fn given_a_valid_create_organization_request_when_processed_then_it_should_succeed() {
    let created_id = Uuid::new_v4();
    let router: Router = setup_state(created_id);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/create")
                .method(http::Method::POST)
                .header(http::header::AUTHORIZATION, "Bearer test")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::new(format!(
                    r###"
                    {{
                        "id": "{created_id}",
                        "name": "Test",
                        "display_name": "Test",
                        "description": "test",
                        "is_enabled": true,
                        "attributes": {{}},
                        "domain": null
                    }}
                    "###
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response
            .headers()
            .get(http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
        format!("/organizations/{}", created_id).as_str()
    )
}

fn create_request(id: Uuid, host: Option<&str>) -> Request {
    let mut builder = Request::builder()
        .uri("/create")
        .method(http::Method::POST)
        .header(http::header::AUTHORIZATION, "Bearer test")
        .header(http::header::CONTENT_TYPE, "application/json");
    if let Some(host) = host {
        builder = builder.header(http::header::HOST, host);
    }
    builder
        .body(Body::new(format!(
            r###"
            {{
                "id": "{id}",
                "name": "Test",
                "display_name": "Test",
                "description": "test",
                "is_enabled": true,
                "attributes": {{}}
            }}
            "###
        )))
        .unwrap()
}

#[tokio::test]
async fn given_a_host_header_when_created_then_the_location_should_stay_relative() {
    let created_id = Uuid::now_v7();
    let router = setup_state(created_id);

    let response = router
        .oneshot(create_request(created_id, Some("api.example.com")))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response.headers().get(http::header::LOCATION).unwrap(),
        format!("/organizations/{}", created_id).as_str()
    )
}

#[tokio::test]
async fn given_a_taken_name_when_created_then_it_should_conflict_on_the_name() {
    let router = setup_state_returning(|| {
        Err(CreateOrganizationError::Database(
            RepositoryWriteError::AlreadyExists {
                entity: "organization".to_string(),
                field: "name",
                value: "Test".to_string(),
            },
        ))
    });

    let response = router
        .oneshot(create_request(Uuid::now_v7(), None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: StatusCodeError = from_slice(&body_bytes).unwrap();
    assert_eq!(json.error_key, "error.organization.name-already-exists");
}

#[tokio::test]
async fn given_malformed_json_when_created_then_it_should_be_a_json_error() {
    let router = setup_state(Uuid::now_v7());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/create")
                .method(http::Method::POST)
                .header(http::header::AUTHORIZATION, "Bearer test")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::new("{ not json".to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: StatusCodeError = from_slice(&body_bytes).unwrap();
    assert_eq!(json.error_key, "error.request.invalid-body");
}

#[tokio::test]
async fn given_a_repository_failure_when_created_then_it_should_return_a_server_error() {
    let router = setup_state_returning(|| {
        Err(CreateOrganizationError::Database(
            RepositoryWriteError::Failure("connection refused: 10.0.0.5:5432".to_string()),
        ))
    });

    let response = router
        .oneshot(create_request(Uuid::now_v7(), None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: StatusCodeError = from_slice(&body_bytes).unwrap();
    assert_eq!(json.error_key, "error.repository.failure");
    assert!(
        !json.description.contains("10.0.0.5"),
        "Leaked database details: {}",
        json.description
    );
}

#[cfg(feature = "e2e")]
#[tokio::test]
async fn given_a_create_organization_request_when_sent_then_it_should_succeed() {
    let TestEnv {
        address,
        access_token,
    } = load_env_and_extract_access_token().await;

    let uuid = Uuid::now_v7().to_string();

    let body = format!(
        r###"
        {{
            "id": "{uuid}",
            "name": "test-2",
            "display_name": "Test 2",
            "description": "test",
            "is_enabled": true,
            "attributes": {{
                "custom-value1": ["value1"],
                "custom-value2": ["value2"]
            }},
            "domain": null
        }}
        "###
    );

    let response = TEST_HTTP_CLIENT
        .post(format!("http://{}/organizations/create", address))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", access_token),
        )
        .body(body)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(response.status().as_u16(), 204);
    assert_eq!(
        response
            .headers()
            .get(http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
        format!("/organizations/{}", uuid)
    )
}
