//! The OAuth proxy of the token handler pattern: a reverse proxy in front of the API and the
//! OAuth agent.
//!
//! It is the single origin the browser talks to. `/api/*` it answers itself: it checks the CSRF
//! header, reads the session the OAuth agent keeps in Redis from the session cookie, and forwards
//! the call to the API with the session's access token instead of the browser's cookies. Everything
//! else (sign-in, the callback, logout, the session, health, the public key set) passes unchanged
//! to the OAuth agent.
//!
//! When the access token is about to expire, the proxy asks the OAuth agent's internal endpoint for
//! a fresh one (`crates/oauth-agent/src/internal.rs`), so it holds no credentials for the identity
//! provider; the OAuth agent refreshes once per session, under the Redis lock.
//!
//! ```text
//! browser ──▶ OAuth proxy ──/api/* (Bearer)──▶ API
//!                 │  └──── everything else ────▶ OAuth agent ◀── POST /internal/access-token
//!                 └──── reads sessions ────────▶ Redis ◀────── the OAuth agent writes them
//! ```
//!
//! Settings: `LISTEN_ADDR` (default `0.0.0.0:5200`), `AGENT_URL` (the OAuth agent, e.g.
//! `http://oauth-agent:5100`), `AGENT_INTERNAL_URL` (e.g. `http://oauth-agent:5101`, which the
//! service mesh protects), `API_BASE_URL`, `REDIS_URI`, `CLIENT_IP_HEADER` and `TRUSTED_PROXIES`
//! (as the OAuth agent's), `METRICS_ADDR` (default `0.0.0.0:9100`), and `RUST_LOG` and
//! `LOG_FORMAT` (see [`token_handler_common::logging`]).
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

mod config;
mod outages;
mod proxy;
mod tokens;

use std::{net::SocketAddr, process::ExitCode};

use tokio::net::TcpListener;
use tracing::{error, info};

use crate::{config::Config, proxy::ProxyState};

/// Sets up logging and runs the proxy until it is stopped; a failure exits with 1.
#[tokio::main]
async fn main() -> ExitCode {
    token_handler_common::logging::init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(%error, "the OAuth proxy stopped");
            ExitCode::FAILURE
        }
    }
}

/// Reads the settings and serves until shut down.
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    let listen_addr = config.listen_addr;
    info!(
        agent_url = %config.agent_url,
        agent_internal_url = %config.agent_internal_url,
        api_base_url = config.api_base_url.as_deref().unwrap_or("none: /api/* answers 503"),
        client_address = %config.client_ip,
        "OAuth proxy configured"
    );
    tokio::spawn(token_handler_common::metrics::serve(config.metrics_addr));

    let app = proxy::router(ProxyState::new(config)?);
    let listener = TcpListener::bind(listen_addr).await?;
    info!("Listening on {}", listener.local_addr()?);
    // The peer address is the client IP for X-Forwarded-For, unless it is a trusted proxy that
    // names the client in its header.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(token_handler_common::shutdown::signal())
    .await?;
    Ok(())
}
