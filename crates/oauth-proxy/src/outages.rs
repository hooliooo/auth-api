//! The dependencies whose outages are logged once, not on every request (see
//! [`token_handler_common::logging::Outage`]).

use token_handler_common::logging::Outage;

/// Redis, where the sessions are read.
pub static REDIS: Outage = Outage::new("redis");
/// The OAuth agent: everything but `/api/*`, and its internal endpoint.
pub static AGENT: Outage = Outage::new("OAuth agent");
/// The API behind `/api/*`.
pub static API: Outage = Outage::new("API");
