use axum::{Router, body::Body, http::Request};
use reqwest::StatusCode;
use tower::ServiceExt;

use crate::common::setup_env_vars;

mod common;

#[tokio::test]
async fn health_check_works() {
    setup_env_vars();
    let app: Router = rest_api::create_router().await;

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
