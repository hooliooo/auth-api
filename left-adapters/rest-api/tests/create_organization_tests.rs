use std::sync::Arc;

use auth_core::{
    application::organization::{
        command_factory::OrganizationCommandFactory, commands::CreateOrganization,
        create::CreateOrganizationError,
    },
    domain::{authorization::authorized_scope::AuthorizedScope, organization::OrganizationId},
};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http,
};
use kern::{
    application::{environment::Environment, use_case::UseCase},
    infrastructure::error::axum_extensions::StatusCodeError,
};
use mockall::mock;
use reqwest::StatusCode;
use rest_api::{
    authorization::jwt::{Claims, ClaimsExtractor, JwtVerificationError, JwtVerifier},
    organization::{CreateOrganizationApplicationService, CreateOrganizationState},
};
use serde_json::from_slice;
use tower::ServiceExt;
use uuid::Uuid;

use crate::common::{TEST_HTTP_CLIENT, TestEnv, load_env_and_extract_access_token};

mod common;

fn setup_state(created_id: Uuid) -> Router {
    let mut use_case = MockTestCreateOrganizationUseCase::new();
    use_case
        .expect_handle()
        .returning(move |_req| Ok(OrganizationId::new(created_id)));
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

    let state: CreateOrganizationState = CreateOrganizationState {
        factory: Arc::new(OrganizationCommandFactory::new(Environment::Development)),
        jwt_verifier: Arc::new(jwt_verifier),
        use_case: Arc::new(use_case) as Arc<CreateOrganizationApplicationService>,
    };

    rest_api::organization::router::create_organization_router(state)
}

mock! {
    pub TestCreateOrganizationUseCase {}

    #[async_trait::async_trait]
    impl UseCase for TestCreateOrganizationUseCase {
        type Request = CreateOrganization;
        type Response = Result<OrganizationId, CreateOrganizationError>;

        async fn handle(&self, request: CreateOrganization) -> Result<OrganizationId, CreateOrganizationError>;
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
        format!("{}/organizations/{}", address, uuid)
    )
}
