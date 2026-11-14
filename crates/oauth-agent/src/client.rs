//! The OAuth agent as a client of the identity provider, and (for the sign-in rate limit) where a
//! request's client address comes from.

pub mod credentials;
#[cfg(feature = "rate-limit")]
pub(crate) use token_handler_common::client_ip as ip;
