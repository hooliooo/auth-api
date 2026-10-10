//! Backend-for-frontend: signs users in with an OpenID Connect provider, keeps their tokens in
//! Redis behind an opaque session cookie, and forwards the SPA's API calls with a bearer token.
//! Configuration and routes: see the crate's README.
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{Router, middleware};
use reqwest::{Client, redirect};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::{
    error::StartupError,
    random::random_token,
    state::{AppState, Oidc, OidcConfig},
};

mod auth;
mod client_ip;
mod cookie;
mod crypto;
mod csrf;
mod env;
mod error;
mod health;
mod pkce;
mod proxy;
mod random;
#[cfg(feature = "rate-limit")]
mod rate_limit;
mod request_id;
mod sealed;
mod session;
mod state;

/// Reads the settings, connects to the identity provider and Redis, and serves until shut down.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let _ = random_token()?;

    let client = Client::builder()
        .redirect(redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;

    let oidc_config = OidcConfig::from_env()?;
    let oidc = Oidc::discover(client.clone(), oidc_config).await?;
    let redis = redis::Client::open(env::env("REDIS_URI")?)?
        .get_connection_manager()
        .await?;

    let api_base_url = std::env::var("API_BASE_URL").ok();
    let api_client = Client::builder()
        .redirect(redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .read_timeout(Duration::from_secs(120))
        .build()?;

    let state = AppState {
        http: client,
        api_http: api_client,
        oidc: Arc::new(oidc),
        redis,
        api_base_url: api_base_url.map(Arc::from),
        client_ip: client_ip::ClientIpSource::from_settings(
            std::env::var("CLIENT_IP_HEADER").ok().as_deref(),
            std::env::var("TRUSTED_PROXIES").ok().as_deref(),
        )?,
        #[cfg(feature = "rate-limit")]
        login_per_minute: std::env::var("LOGIN_RATE_LIMIT_PER_MINUTE")
            .ok()
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| StartupError::InvalidSetting("LOGIN_RATE_LIMIT_PER_MINUTE"))
            })
            .transpose()?
            .unwrap_or(10),
    };

    let app = Router::new()
        .merge(auth::routes())
        .merge(proxy::routes())
        .merge(health::routes())
        .layer(middleware::from_fn(csrf::require_header))
        // Outermost, so even requests the CSRF check refuses get an id.
        .layer(middleware::from_fn(request_id::assign))
        .with_state(state);
    let listen_addr: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:5100".to_owned())
        .parse()
        .map_err(|_| StartupError::InvalidSetting("LISTEN_ADDR"))?;
    let listener = TcpListener::bind(listen_addr).await?;
    info!("Listening on {}", listener.local_addr()?);

    // The peer address is the fallback client IP for rate limiting and X-Forwarded-For.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

/// Completes on Ctrl-C or SIGTERM (container stop, rollout), so in-flight requests can
/// finish before the process exits.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "Cannot listen for Ctrl + C");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::warn!(%error, "Cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>().await;

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    info!("Shutting down");
}
