//! Liveness (`/health`) and readiness (`/health/ready`, which needs Redis) checks.

use axum::{Router, extract::State, http::StatusCode, routing::get};
use tracing::warn;

use crate::state::AppState;

/// Routes for the health checks
pub fn routes() -> Router<AppState> {
    health().route("/health/ready", get(ready))
}

/// Health check endpoint
fn health<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new().route("/health", get(|| async { StatusCode::OK }))
}

/// Health check endpoint for Redis
async fn ready(State(app_state): State<AppState>) -> StatusCode {
    let mut redis = app_state.redis.clone();
    match redis::cmd("PING").query_async::<String>(&mut redis).await {
        Ok(_) => StatusCode::OK,
        Err(error) => {
            warn!(%error, "Redis is unreachable");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use reqwest::StatusCode;
    use tower::ServiceExt;

    use crate::health::health;

    #[tokio::test]
    async fn given_health_endpoint_when_queried_then_it_should_succeed() {
        let app = health::<()>();

        let response = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
