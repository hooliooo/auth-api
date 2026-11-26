//! How a session cookie becomes an access token: the session the OAuth agent keeps in Redis, or,
//! when its token is about to expire, a fresh one from the OAuth agent's internal endpoint
//! (`crates/oauth-agent/src/internal.rs`). The proxy holds no credentials for the identity
//! provider; the OAuth agent refreshes once per session, under its Redis lock. The service mesh
//! encrypts the call and is what lets the proxy, and only the proxy, reach that endpoint.

use std::{sync::Arc, time::Duration};

use axum::http::StatusCode;
use redis::{AsyncCommands, aio::ConnectionManager};
use token_handler_common::{
    causes::with_causes,
    internal::{AccessToken, PATH, SESSION_HEADER},
    session::{self, session_key},
};
use tokio::sync::OnceCell;
use tracing::warn;

/// Total time the OAuth agent's internal endpoint may take; it may wait on the identity provider.
const INTERNAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Where access tokens come from. Cheap to clone.
#[derive(Clone)]
pub struct Tokens {
    /// Redis, connected on first use, so the proxy starts without it.
    redis: Arc<OnceCell<ConnectionManager>>,
    /// `REDIS_URI`.
    redis_uri: Arc<str>,
    /// For the OAuth agent's internal endpoint.
    http: reqwest::Client,
    /// The internal endpoint's URL.
    internal_url: Arc<str>,
}

impl Tokens {
    /// Tokens from the sessions in `redis_uri`, refreshed through the OAuth agent's internal
    /// endpoint at `agent_internal_url`.
    pub fn new(
        redis_uri: &str,
        agent_internal_url: &str,
        connect_timeout: Duration,
    ) -> reqwest::Result<Self> {
        Ok(Self {
            redis: Arc::new(OnceCell::new()),
            redis_uri: redis_uri.into(),
            http: reqwest::Client::builder()
                .connect_timeout(connect_timeout)
                .timeout(INTERNAL_TIMEOUT)
                .build()?,
            internal_url: format!("{agent_internal_url}{PATH}").into(),
        })
    }

    /// The Redis connection, made on first use; 503 while Redis cannot be reached.
    async fn redis(&self) -> Result<ConnectionManager, StatusCode> {
        self.redis
            .get_or_try_init(|| async {
                redis::Client::open(&*self.redis_uri)?
                    .get_connection_manager()
                    .await
            })
            .await
            .cloned()
            .map_err(|error| {
                warn!(error = %with_causes(&error), "Redis unavailable");
                StatusCode::SERVICE_UNAVAILABLE
            })
    }

    /// An access token for session `sid` valid for at least another minute: the session's own, or a
    /// fresh one from the OAuth agent. `None` if the session is gone or has ended; otherwise the
    /// status to answer: 503 if Redis or the identity provider is unavailable, 502 if the OAuth
    /// agent cannot be reached or answers unexpectedly.
    pub async fn access_token(&self, sid: &str) -> Result<Option<String>, StatusCode> {
        let mut redis = self.redis().await?;
        let raw: Option<Vec<u8>> = redis.get(session_key(sid)).await.map_err(|error| {
            warn!(error = %with_causes(&error), "session not read");
            StatusCode::SERVICE_UNAVAILABLE
        })?;
        let Some(session) = raw.and_then(|raw| session::open(sid, &raw)) else {
            return Ok(None);
        };
        if let Some(token) = session.usable_access_token() {
            return Ok(Some(token.to_owned()));
        }
        // Expiring, or past the 24-hour cap: the OAuth agent refreshes or ends it.
        let response = self
            .http
            .post(&*self.internal_url)
            .header(SESSION_HEADER, sid)
            .send()
            .await
            .map_err(|error| {
                warn!(error = %with_causes(&error), "the OAuth agent's internal endpoint is unreachable");
                StatusCode::BAD_GATEWAY
            })?;
        match response.status() {
            StatusCode::OK => {
                let fresh: AccessToken =
                    response.json().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
                Ok(Some(fresh.access_token))
            }
            StatusCode::UNAUTHORIZED => Ok(None),
            status @ (StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE) => Err(status),
            status => {
                warn!(%status, "the OAuth agent's internal endpoint answered unexpectedly");
                Err(StatusCode::BAD_GATEWAY)
            }
        }
    }
}
