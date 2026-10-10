//! Fixed-window rate limits in Redis, shared by every BFF instance.

use std::net::IpAddr;

use redis::aio::ConnectionManager;

use crate::{error::AppError, session::now};

/// Length of one counting window.
const WINDOW_SECS: u64 = 60;

/// Counts one sign-in start for `client` in `redis` and refuses once it exceeds `per_minute`
/// in the current minute. `per_minute == 0` turns the limit off.
pub async fn check_login(
    redis: &mut ConnectionManager,
    client: IpAddr,
    per_minute: u32,
) -> Result<(), AppError> {
    if per_minute == 0 {
        return Ok(());
    }
    let now = now();
    let window = now / WINDOW_SECS;
    let key = format!("bff:rl:login:{client}:{window}");
    // EXPIRE NX sets the expiry only on the first hit, so the key dies with its window.
    let (count,): (u64,) = redis::pipe()
        .atomic()
        .incr(&key, 1)
        .cmd("EXPIRE")
        .arg(&key)
        .arg(WINDOW_SECS)
        .arg("NX")
        .ignore()
        .query_async(redis)
        .await?;
    if count > u64::from(per_minute) {
        let retry_after = WINDOW_SECS - now % WINDOW_SECS;
        return Err(AppError::TooManyRequests { retry_after });
    }
    Ok(())
}
