//! Backend-for-frontend: signs users in with an OpenID Connect provider, keeps their tokens in
//! Redis behind an opaque session cookie, and forwards the SPA's API calls with a bearer token.
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

use std::{
    net::{Ipv4Addr, SocketAddr},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use axum::{Router, middleware};
use reqwest::{Client, redirect};
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::{
    client::ip::ClientIpSource,
    random::random_token,
    state::{AppState, Oidc, OidcConfig},
};

mod auth;
mod client;
mod cookie;
mod crypto;
mod csrf;
mod env;
mod error;
mod health;
mod identity_provider;
mod metrics;
mod pkce;
mod proxy;
mod random;
#[cfg(feature = "rate-limit")]
mod rate_limit;
mod request;
mod sealed;
mod session;
mod state;
mod time;

/// Total time a call to the identity provider may take: sign-ins and logouts wait on it.
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(10);
/// Time to open a connection to the API.
const API_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest the API may stay silent between two reads; a response that keeps streaming is
/// never cut off.
const API_READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Sets up logging and runs the BFF; a failure is logged with its message and exits with 1.
#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        // `info` unless RUST_LOG says otherwise; the default would drop every warning.
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(%error, "the BFF stopped");
            ExitCode::FAILURE
        }
    }
}

/// Reads the settings, connects to the identity provider and Redis, and serves until shut down.
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Fail now rather than on the first sign-in if the random source is broken.
    let _ = random_token()?;

    // Discovery waits for a provider that is still starting, e.g. Keycloak in the same rollout.
    let http = Client::builder()
        .redirect(redirect::Policy::none())
        .timeout(PROVIDER_TIMEOUT)
        .build()?;
    let oidc = Oidc::discover(http.clone(), OidcConfig::from_env()?).await?;
    let redis = redis::Client::open(env::env("REDIS_URI")?)?
        .get_connection_manager()
        .await?;

    let api_http = Client::builder()
        .redirect(redirect::Policy::none())
        .connect_timeout(API_CONNECT_TIMEOUT)
        .read_timeout(API_READ_TIMEOUT)
        .build()?;

    let state = AppState {
        http,
        redis,
        oidc: Arc::new(oidc),
        api_http,
        api_base_url: std::env::var("API_BASE_URL").ok().map(Arc::from),
        client_ip: ClientIpSource::from_settings(
            std::env::var("CLIENT_IP_HEADER").ok().as_deref(),
            std::env::var("TRUSTED_PROXIES").ok().as_deref(),
        )?,
        #[cfg(feature = "rate-limit")]
        login_per_minute: env::parsed_or("LOGIN_RATE_LIMIT_PER_MINUTE", 10)?,
    };

    let app = Router::new()
        .merge(auth::routes())
        .merge(client::credentials::routes())
        .merge(proxy::routes())
        .merge(health::routes())
        .layer(middleware::from_fn(csrf::require_header));
    // Outside the CSRF check, so refused requests are counted too.
    #[cfg(feature = "metrics")]
    let app = app.layer(middleware::from_fn(metrics::track));
    let app = app
        // Outermost, so even requests the CSRF check refuses get an id.
        .layer(middleware::from_fn(request::assign))
        .with_state(state);

    let listen_addr = env::parsed_or(
        "LISTEN_ADDR",
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 5100)),
    )?;
    let listener = TcpListener::bind(listen_addr).await?;
    info!("Listening on {}", listener.local_addr()?);

    #[cfg(feature = "metrics")]
    {
        let metrics_addr = env::parsed_or(
            "METRICS_ADDR",
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 9100)),
        )?;
        tokio::spawn(metrics::serve(metrics_addr));
    }

    // The peer address is the client IP for rate limiting and X-Forwarded-For, unless it is a
    // trusted proxy that names the client in its header.
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
            warn!(%error, "Cannot listen for Ctrl + C");
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
                warn!(%error, "Cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    info!("Shutting down");
}
