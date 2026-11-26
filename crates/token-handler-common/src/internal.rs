//! The OAuth agent's internal endpoint, as both sides use it: the OAuth proxy asks it for a fresh
//! access token when the session's own is about to expire, so only the agent refreshes and holds
//! the client's credentials. The service mesh authenticates the proxy and encrypts the call, so
//! the request carries only the session id. One definition, so the two can never disagree on the
//! request or the answer.

use serde::{Deserialize, Serialize};

/// The endpoint's path, on the agent's internal address (`INTERNAL_ADDR`).
pub const PATH: &str = "/internal/access-token";
/// Header carrying the session id, the value of the browser's session cookie.
pub const SESSION_HEADER: &str = "x-session-id";

/// The endpoint's answer.
#[derive(Debug, Deserialize, Serialize)]
pub struct AccessToken {
    /// An access token valid for at least another minute.
    pub access_token: String,
}
