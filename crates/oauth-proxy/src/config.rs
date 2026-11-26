//! The OAuth proxy's settings, read once at startup.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use thiserror::Error;
use token_handler_common::{
    client_ip::{ClientIpError, ClientIpSource},
    env::{self, EnvError},
};

/// Why the proxy cannot start.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// A setting is missing or cannot be parsed.
    #[error(transparent)]
    Env(#[from] EnvError),
    /// The client IP settings cannot be used.
    #[error(transparent)]
    ClientIp(#[from] ClientIpError),
}

/// The proxy's settings.
pub struct Config {
    /// `LISTEN_ADDR`: the public address.
    pub listen_addr: SocketAddr,
    /// `AGENT_URL`: the OAuth agent, which answers everything but `/api/*`, e.g.
    /// `http://oauth-agent:5100`.
    pub agent_url: String,
    /// `AGENT_INTERNAL_URL`: the OAuth agent's internal endpoint, for fresh access tokens, e.g.
    /// `http://oauth-agent:5101`; the service mesh encrypts the call and vouches for the proxy.
    pub agent_internal_url: String,
    /// `API_BASE_URL`, e.g. `http://api:8080/v1`; without it, `/api/*` answers 503.
    pub api_base_url: Option<String>,
    /// `REDIS_URI`: the OAuth agent's sessions.
    pub redis_uri: String,
    /// `CLIENT_IP_HEADER` and `TRUSTED_PROXIES`, as the OAuth agent's.
    pub client_ip: ClientIpSource,
    /// `METRICS_ADDR`.
    pub metrics_addr: SocketAddr,
}

/// Time to open a connection to the API or the OAuth agent.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest the API or the OAuth agent may stay silent between two reads; a response that keeps
/// streaming is never cut off. The same as the OAuth agent's.
pub const READ_TIMEOUT: Duration = Duration::from_secs(120);

/// The `http(s)://` URL in variable `name`, without a trailing slash.
fn url(name: &'static str, value: &str) -> Result<String, EnvError> {
    if !(value.starts_with("http://") || value.starts_with("https://")) {
        return Err(EnvError::Invalid(name));
    }
    Ok(value.trim_end_matches('/').to_owned())
}

impl Config {
    /// Reads and checks every setting.
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            listen_addr: env::parsed_or(
                "LISTEN_ADDR",
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 5200)),
            )?,
            agent_url: url("AGENT_URL", &env::required("AGENT_URL")?)?,
            agent_internal_url: url("AGENT_INTERNAL_URL", &env::required("AGENT_INTERNAL_URL")?)?,
            api_base_url: match std::env::var("API_BASE_URL") {
                Ok(value) => Some(url("API_BASE_URL", &value)?),
                Err(_) => None,
            },
            redis_uri: env::required("REDIS_URI")?,
            client_ip: ClientIpSource::from_env()?,
            metrics_addr: env::parsed_or(
                "METRICS_ADDR",
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 9100)),
            )?,
        })
    }
}
