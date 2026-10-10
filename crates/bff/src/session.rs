use axum::extract::FromRequestParts;
use core::fmt;
use redis::{AsyncCommands, Script, aio::ConnectionManager};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::warn;

use crate::{
    cookie,
    crypto::hash_key,
    error::AppError,
    random::random_token,
    sealed::{self, Purpose},
    state::AppState,
};

pub const SSO_IDLE_SECS: u64 = 3_600;
pub const SSO_MAX_SECS: u64 = 24 * 3_600;
const REFRESH_ACCESS_TOKEN_AHEAD_SECS: u64 = 60;
const REFRESH_LOCK_MILLIS: u64 = 30_000;
const REFRESH_LOCK_WAIT: Duration = Duration::from_secs(12);
const REFRESH_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Writes the session only if this caller still holds the refresh lock and the session still
/// exists, so a refresh can neither race another instance nor bring back a logged-out session.
const WRITE_IF_LOCK_HELD: &str = "\
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end \
if redis.call('SET', KEYS[2], ARGV[2], 'XX', 'EX', ARGV[3]) then return 1 end \
return 0";

/// Deletes the lock only if it is still ours.
const RELEASE_LOCK: &str = "\
if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end \
return 0";

#[derive(Deserialize, Serialize)]
pub struct Session {
    pub sub: String,
    pub sid: Option<String>,
    pub id_token: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: u64,
    pub created_at: u64,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("sub", &self.sub)
            .finish_non_exhaustive()
    }
}

pub fn now() -> u64 {
    let now = time::UtcDateTime::now();
    now.unix_timestamp() as u64
}

fn session_key(hashed: &str) -> String {
    format!("bff:session:{hashed}")
}

fn iam_index_key(iam_sid: &str) -> String {
    format!("bff:iam-sid:{iam_sid}")
}

fn lock_key(sid: &str) -> String {
    format!("bff:lock:{}", hash_key(sid))
}

fn seal(sid: &str, session: &Session) -> Result<Vec<u8>, AppError> {
    Ok(sealed::seal(
        sid,
        sealed::Purpose::Session,
        &serde_json::to_vec(session)?,
    )?)
}

pub async fn load(redis: &mut ConnectionManager, sid: &str) -> Result<Option<Session>, AppError> {
    let raw: Option<Vec<u8>> = redis::cmd("GETEX")
        .arg(session_key(&hash_key(sid)))
        .arg("EX")
        .arg(SSO_IDLE_SECS)
        .query_async(redis)
        .await?;
    let Some(plaintext) = raw.and_then(|raw| sealed::open(sid, Purpose::Session, &raw)) else {
        return Ok(None);
    };

    let session: Session = serde_json::from_slice(&plaintext)?;

    if now().saturating_sub(session.created_at) > SSO_MAX_SECS {
        delete(redis, sid, session.sid.as_deref()).await?;
        return Ok(None);
    }
    Ok(Some(session))
}

pub async fn save(
    redis: &mut ConnectionManager,
    sid: &str,
    session: &Session,
) -> Result<(), AppError> {
    let hashed = hash_key(sid);
    let mut pipe = redis::pipe();
    pipe.atomic()
        .set_ex(session_key(&hashed), seal(sid, session)?, SSO_IDLE_SECS)
        .ignore();

    if let Some(kc_sid) = session.sid.as_deref() {
        let index = iam_index_key(kc_sid);
        pipe.sadd(&index, &hashed)
            .ignore()
            .expire(&index, SSO_MAX_SECS as i64)
            .ignore();
    }
    pipe.query_async::<()>(redis).await?;
    Ok(())
}

pub async fn delete(
    redis: &mut ConnectionManager,
    sid: &str,
    iam_sid: Option<&str>,
) -> Result<(), AppError> {
    let hashed = hash_key(sid);
    let mut pipe = redis::pipe();
    pipe.atomic().del(session_key(&hashed)).ignore();
    if let Some(iam_sid) = iam_sid {
        pipe.srem(iam_index_key(iam_sid), &hashed).ignore();
    }
    pipe.query_async::<()>(redis).await?;
    Ok(())
}

pub async fn delete_by_iam_sid(
    redis: &mut ConnectionManager,
    sid: &str,
) -> Result<usize, AppError> {
    let index = iam_index_key(sid);
    let hashed: Vec<String> = redis.smembers(&index).await?;

    let keys: Vec<String> = hashed.iter().map(|h| session_key(h)).collect();
    if !keys.is_empty() {
        redis.del::<_, ()>(&keys).await?;
    }
    redis.del::<_, ()>(&index).await?;
    Ok(keys.len())
}

pub struct CurrentSession {
    pub id: String,
    pub session: Session,
}

impl FromRequestParts<AppState> for CurrentSession {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, AppError> {
        let id = cookie::get(&parts.headers, cookie::SESSION).ok_or(AppError::Unauthorized)?;
        let mut redis = state.redis.clone();
        let session = load(&mut redis, &id).await?.ok_or(AppError::Unauthorized)?;
        Ok(Self { id, session })
    }
}

struct RefreshLock {
    key: String,
    token: String,
}

impl RefreshLock {
    /// 'None' if another instance still holds the lock past REFRESH_LOCK_WAIT
    async fn acquire(redis: &mut ConnectionManager, sid: &str) -> Result<Option<Self>, AppError> {
        let lock = Self {
            key: lock_key(sid),
            token: random_token()?,
        };

        let poll = Duration::from_millis(50);
        let attempts = REFRESH_LOCK_WAIT.as_millis() / poll.as_millis();

        for _ in 0..attempts {
            let acquired: Option<String> = redis::cmd("SET")
                .arg(&lock.key)
                .arg(&lock.token)
                .arg("NX")
                .arg("PX")
                .arg(REFRESH_LOCK_MILLIS)
                .query_async(redis)
                .await?;

            if acquired.is_some() {
                return Ok(Some(lock));
            }

            tokio::time::sleep(poll).await;
        }
        Ok(None)
    }

    async fn release(self, redis: &mut ConnectionManager) {
        let result: Result<i64, _> = Script::new(RELEASE_LOCK)
            .key(&self.key)
            .arg(&self.token)
            .invoke_async(redis)
            .await;
        if let Err(error) = result {
            warn!(%error, "could not release refresh lock; it will expire");
        }
    }
}

/// Refreshes the access token for the current session if needed. 'None' means the session is gone
/// or cannot be refreshed.
pub async fn refresh_access_token(
    app_state: &AppState,
    current_session: CurrentSession,
) -> Result<Option<String>, AppError> {
    if current_session.session.expires_at > now() + REFRESH_ACCESS_TOKEN_AHEAD_SECS {
        return Ok(Some(current_session.session.access_token));
    }

    let sid = current_session.id;
    let mut redis = app_state.redis.clone();
    let Some(lock) = RefreshLock::acquire(&mut redis, &sid).await? else {
        warn!("token refresh is happening elsewhere; not proceeding");
        return Ok(None);
    };

    let result = refresh_locked(app_state, &mut redis, &sid, &lock).await;
    lock.release(&mut redis).await;
    result
}

#[derive(Deserialize)]
struct RefreshResponse {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    expires_in: u64,
}

async fn refresh_locked(
    app_state: &AppState,
    redis: &mut ConnectionManager,
    sid: &str,
    lock: &RefreshLock,
) -> Result<Option<String>, AppError> {
    let Some(mut session) = load(redis, sid).await? else {
        return Ok(None);
    };

    if session.expires_at > now() + REFRESH_ACCESS_TOKEN_AHEAD_SECS {
        return Ok(Some(session.access_token));
    }

    let Some(refresh_token) = session.refresh_token.clone() else {
        delete(redis, sid, session.sid.as_deref()).await?;
        return Ok(None);
    };

    let response = app_state
        .http
        .post(app_state.oidc.token_endpoint())
        .timeout(REFRESH_REQUEST_TIMEOUT)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
            ("client_id", app_state.client_id()),
            ("client_secret", app_state.client_secret()),
        ])
        .send()
        .await
        .map_err(|e| AppError::RefreshAccessTokenFailed(e.to_string()))?;

    match response.status() {
        status if status.is_success() => {}
        StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED => {
            warn!(status = %response.status(), "refresh token rejected; ending session");
            delete(redis, sid, session.sid.as_deref()).await?;
            return Ok(None);
        }
        status => {
            return Err(AppError::RefreshAccessTokenFailed(format!(
                "token endpoint returned {status}"
            )));
        }
    }

    let response: RefreshResponse = response
        .json()
        .await
        .map_err(|e| AppError::RefreshAccessTokenFailed(e.to_string()))?;
    session.access_token = response.access_token;
    if let Some(new_refresh_token) = response.refresh_token {
        session.refresh_token = Some(new_refresh_token);
    }

    if let Some(new_id_token) = response.id_token {
        session.id_token = new_id_token;
    }

    session.expires_at = now() + response.expires_in;

    let written: i64 = Script::new(WRITE_IF_LOCK_HELD)
        .key(&lock.key)
        .key(session_key(&hash_key(sid)))
        .arg(&lock.token)
        .arg(seal(sid, &session)?)
        .arg(SSO_IDLE_SECS)
        .invoke_async(redis)
        .await?;
    if written == 0 {
        // Lock lost to another instance or the session expired/logged out
        return Ok(None);
    }
    Ok(Some(session.access_token))
}
