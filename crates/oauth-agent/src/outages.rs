//! The dependencies whose outages are logged once, not on every request (see
//! [`token_handler_common::logging::Outage`]).

use token_handler_common::logging::Outage;

/// Redis: sessions, sign-ins, locks and limits.
pub static REDIS: Outage = Outage::new("redis");
/// The identity provider's token endpoint and signing keys.
pub static PROVIDER: Outage = Outage::new("identity provider");
