//! What the token handler's two parts share, so both apply one set of rules: the OAuth agent
//! signs users in and keeps their sessions; the OAuth proxy turns a session cookie into a bearer
//! token on every API call. Together they are the Backend for Frontend (BFF) of RFC 10017 §6.1.
//! Here: the session format and its
//! sealing, the session cookie, the CSRF check, request ids, client addresses, the metrics and
//! their server, logging and graceful shutdown. What reaches the API is the OAuth proxy's alone
//! (`crates/oauth-proxy/src/proxy.rs`).
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

pub mod client_ip;
pub mod cookie;
pub mod crypto;
pub mod csrf;
pub mod logging;
pub mod metrics;
pub mod random;
pub mod request_id;
pub mod sealed;
pub mod session;
pub mod shutdown;
pub mod time;
