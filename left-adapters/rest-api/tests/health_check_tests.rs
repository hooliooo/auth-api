use axum::{Router, body::Body, http::Request};
use reqwest::StatusCode;
use tower::ServiceExt;

mod common;

#[tokio::test]
async fn health_check_works() {
    let app: Router = rest_api::create_health_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
