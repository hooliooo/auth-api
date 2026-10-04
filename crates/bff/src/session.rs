use core::fmt;

use axum::extract::FromRequestParts;
use redis::{AsyncCommands, aio::ConnectionManager};
use serde::{Deserialize, Serialize};

use crate::{cookie, crypto::hash_key, error::AppError, state::AppState};

pub const SSO_IDLE_SECS: u64 = 1 * 3_600;
pub const SSO_MAX_SECS: u64 = 24 * 3_600;
const REFRESH_ACCESS_TOKEN_AHEAD_SECS: u64 = 60;
const REFRESH_LOCK_MILLIS: u64 = 10_000;

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

fn kc_index_key(sid: &str) -> String {
    format!("bff:kc-sid:{sid}")
}

fn lock_key(sid: &str) -> String {
    format!("bff:lock:{}", hash_key(sid))
}

pub async fn load(redis: &mut ConnectionManager, sid: &str) -> Result<Option<Session>, AppError> {
    let raw: Option<String> = redis::cmd("GETEX")
        .arg(session_key(&hash_key(sid)))
        .arg("EX")
        .arg(SSO_IDLE_SECS)
        .query_async(redis)
        .await?;
    let Some(session) = raw
        .map(|s| serde_json::from_str::<Session>(&s))
        .transpose()?
    else {
        return Ok(None);
    };

    if now().saturating_sub(session.created_at) > SSO_MAX_SECS {
        delete(redis, sid).await?;
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
        .set_ex(
            session_key(&hashed),
            serde_json::to_string(session)?,
            SSO_IDLE_SECS,
        )
        .ignore();

    if let Some(kc_sid) = session.sid.as_deref() {
        let index = kc_index_key(kc_sid);
        pipe.sadd(&index, &hashed)
            .ignore()
            .expire(&index, SSO_MAX_SECS as i64)
            .ignore();
    }
    pipe.query_async::<()>(redis).await?;
    Ok(())
}

pub async fn delete(redis: &mut ConnectionManager, sid: &str) -> Result<(), AppError> {
    redis.del::<_, ()>(session_key(&hash_key(sid))).await?;
    Ok(())
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
