use axum::{Router, extract::State, http::StatusCode, routing::get};
use tracing::warn;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .route("/health/ready", get(ready))
}

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
