//! The session record the OAuth agent keeps per signed-in browser, sealed in Redis under a hash of
//! the session id; the session id itself is the cookie's value and the key that opens the record,
//! so Redis alone yields no tokens. The OAuth agent writes sessions; the OAuth proxy only reads
//! them.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    crypto::hash_key,
    sealed::{self, Purpose},
    time::now,
};

/// The OAuth agent's own cap: a session ends this long after sign-in, whatever the provider allows.
pub const SSO_MAX_SECS: u64 = 24 * 3_600;
/// Refresh the access token when it has less than this left.
const REFRESH_AHEAD_SECS: u64 = 60;

/// What the OAuth agent keeps per signed-in browser, sealed in Redis under the session id.
#[derive(Deserialize, Serialize)]
pub struct Session {
    /// The user's id.
    pub sub: String,
    /// The identity provider's session id, for back-channel logout.
    pub sid: Option<String>,
    /// The latest ID token; the hint for logout.
    pub id_token: String,
    /// Bearer token for the API.
    pub access_token: String,
    /// Renews `access_token`.
    pub refresh_token: Option<String>,
    /// When `access_token` expires, in Unix seconds.
    pub expires_at: u64,
    /// When the user signed in, in Unix seconds; the 24-hour cap counts from here.
    pub created_at: u64,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("sub", &self.sub)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Whether the session is past the 24-hour cap.
    pub fn past_cap(&self) -> bool {
        now().saturating_sub(self.created_at) > SSO_MAX_SECS
    }

    /// The access token, if it is valid for at least another minute (`REFRESH_AHEAD_SECS`) and the
    /// session is within its cap; otherwise the OAuth agent must refresh it or end the session.
    pub fn usable_access_token(&self) -> Option<&str> {
        (!self.past_cap() && self.expires_at > now() + REFRESH_AHEAD_SECS)
            .then_some(self.access_token.as_str())
    }
}

/// Redis key of the session whose session id is `sid`.
pub fn session_key(sid: &str) -> String {
    session_key_hashed(&hash_key(sid))
}

/// Redis key of the session whose hashed id is `hashed`.
pub fn session_key_hashed(hashed: &str) -> String {
    format!("token-handler:session:{hashed}")
}

/// Redis key of the set of sessions belonging to provider session `iam_sid`.
pub fn iam_index_key(iam_sid: &str) -> String {
    format!("token-handler:iam-sid:{iam_sid}")
}

/// The session sealed in `raw`, opened with session id `sid`; `None` if it does not open or
/// read.
pub fn open(sid: &str, raw: &[u8]) -> Option<Session> {
    let plaintext = sealed::open(sid, Purpose::Session, raw)?;
    serde_json::from_slice(&plaintext).ok()
}
