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
//! The endpoint is plain HTTP and trusts every request it receives: the service mesh (Istio, in
//! ambient mode) encrypts the link with mutual TLS and its AuthorizationPolicy admits only the
//! OAuth proxy's service account to this port (`deploy/k8s/oauth-agent`). So the agent opens it
//! only when `INTERNAL_ENDPOINT=mesh` declares that protection; without the setting there is no
//! internal endpoint, and any other value stops startup.

use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::post,
};

use token_handler_common::internal::{AccessToken, PATH, SESSION_HEADER};

use crate::{
    error::{AppError, StartupError},
    session::{self, CurrentSession, refresh_access_token},
    state::AppState,
};

/// Whether to serve the endpoint: `INTERNAL_ENDPOINT=mesh`, the declaration that the service mesh
/// protects it; unset means no endpoint, anything else is refused.
pub fn enabled() -> Result<bool, StartupError> {
    enabled_by(std::env::var("INTERNAL_ENDPOINT").ok().as_deref())
}

/// [`enabled`] for the setting's value `setting`.
fn enabled_by(setting: Option<&str>) -> Result<bool, StartupError> {
    match setting {
        None => Ok(false),
        Some("mesh") => Ok(true),
        Some(_) => Err(StartupError::InvalidSetting("INTERNAL_ENDPOINT")),
    }
}

/// `POST /internal/access-token`.
pub fn routes() -> Router<AppState> {
    Router::new().route(PATH, post(access_token))
}

/// `POST /internal/access-token` with [`SESSION_HEADER`] in `headers`, from the OAuth proxy (the
/// mesh admits no one else): an access token for the session valid for at least another minute,
/// refreshed at the identity provider if needed. 401 for a session that is gone, past its cap, or
/// whose refresh token the provider rejects (the session then ends); 502 or 503 if the provider or
/// Redis is unavailable.
async fn access_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let id = headers
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?
        .to_owned();
    let mut redis = state.redis.clone();
    let session = session::load(&mut redis, &id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let access_token = refresh_access_token(&state, CurrentSession { id, session })
        .await?
        .ok_or(AppError::Unauthorized)?;
    Ok(Json(AccessToken { access_token }).into_response())
}

#[cfg(test)]
mod tests {
    use super::enabled_by;

    #[test]
    fn given_the_mesh_declared_then_the_endpoint_is_served() {
        assert!(enabled_by(Some("mesh")).unwrap());
    }

    #[test]
    fn given_no_setting_then_there_is_no_endpoint() {
        assert!(!enabled_by(None).unwrap());
    }

    #[test]
    fn given_any_other_value_then_startup_stops() {
        for value in ["", "true", "on", "tls", "MESH"] {
            assert!(enabled_by(Some(value)).is_err(), "{value:?}");
        }
    }
}
