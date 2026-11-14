//! The OAuth agent's internal endpoint for the OAuth proxy, on its own address (`INTERNAL_ADDR`),
//! never behind the ingress.
//!
//! In the token handler split, the OAuth proxy (`crates/oauth-proxy`) answers `/api/*`: it reads
//! the session from Redis and forwards the call with the session's access token. When that token is
//! about to expire, it asks the OAuth agent here for a fresh one instead of refreshing itself, so
//! only the OAuth agent holds the client's credentials for the identity provider. The OAuth agent
//! refreshes with [`crate::session::refresh_access_token`]: once per session across every instance,
//! under the Redis lock.
//!
//! Only callers with the shared secret (`INTERNAL_SECRET_FILE`) are served.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Serialize;

use crate::{
    crypto::constant_time_eq,
    error::AppError,
    session::{self, CurrentSession, refresh_access_token},
    state::AppState,
};

/// Header carrying the shared secret.
pub const SECRET_HEADER: &str = "x-internal-secret";
/// Header carrying the session id, the value of the browser's session cookie.
pub const SESSION_HEADER: &str = "x-session-id";

/// The internal endpoint's state: the OAuth agent's, and the secret callers must send.
#[derive(Clone)]
pub struct InternalState {
    /// The OAuth agent's state.
    pub app: AppState,
    /// The shared secret.
    pub secret: Arc<str>,
}

/// Answer of `POST /internal/access-token`.
#[derive(Serialize)]
struct AccessToken {
    /// An access token valid for at least another minute.
    access_token: String,
}

/// `POST /internal/access-token`.
pub fn routes() -> Router<InternalState> {
    Router::new().route("/internal/access-token", post(access_token))
}

/// `POST /internal/access-token` with [`SECRET_HEADER`] and [`SESSION_HEADER`] in `headers`: an
/// access token for the session valid for at least another minute, refreshed at the identity
/// provider if needed. 401 for a wrong secret, or a session that is gone, past its cap, or whose
/// refresh token the provider rejects (the session then ends); 502 or 503 if the provider or
/// Redis is unavailable.
async fn access_token(
    State(state): State<InternalState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let header = |name| headers.get(name).and_then(|v| v.to_str().ok());
    if !header(SECRET_HEADER).is_some_and(|secret| constant_time_eq(secret, &state.secret)) {
        return Err(AppError::Unauthorized);
    }
    let id = header(SESSION_HEADER)
        .ok_or(AppError::Unauthorized)?
        .to_owned();
    let mut redis = state.app.redis.clone();
    let session = session::load(&mut redis, &id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let access_token = refresh_access_token(&state.app, CurrentSession { id, session })
        .await?
        .ok_or(AppError::Unauthorized)?;
    Ok(Json(AccessToken { access_token }).into_response())
}
