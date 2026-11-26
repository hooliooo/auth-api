//! The OAuth agent of the token handler pattern: signs users in with an OpenID Connect provider and
//! keeps their tokens in Redis behind an opaque session cookie. The OAuth proxy
//! (`crates/oauth-proxy`) answers the SPA's API calls with those tokens and asks the OAuth agent's
//! internal endpoint for fresh ones, so only the OAuth agent holds the client's credentials.
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
use tracing::{error, info};

use token_handler_common::{csrf::PathRule, env, random::random_token};

use crate::state::{AppState, Oidc, OidcConfig};
#[cfg(feature = "rate-limit")]
use token_handler_common::client_ip::ClientIpSource;

mod auth;
mod client;
mod csrf;
mod error;
mod health;
mod identity_provider;
mod internal;
mod metrics;
mod outages;
mod pkce;
#[cfg(feature = "rate-limit")]
mod rate_limit;
mod session;
mod state;

/// Total time a call to the identity provider may take: sign-ins and logouts wait on it.
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(10);

/// Sets up logging and runs the OAuth agent; a failure is logged with its message and exits with 1.
#[tokio::main]
async fn main() -> ExitCode {
    token_handler_common::logging::init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(%error, "the OAuth agent stopped");
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
    let redis = redis::Client::open(env::required("REDIS_URI")?)?
        .get_connection_manager()
        .await?;

    let state = AppState {
        http,
        redis,
        oidc: Arc::new(oidc),
        #[cfg(feature = "rate-limit")]
        client_ip: ClientIpSource::from_env()?,
        #[cfg(feature = "rate-limit")]
        login_per_minute: env::parsed_or("LOGIN_RATE_LIMIT_PER_MINUTE", 10)?,
    };

    let app = Router::new()
        .merge(auth::routes())
        .merge(client::credentials::routes())
        .merge(health::routes())
        .layer(middleware::from_fn_with_state(
            csrf::needs_header as PathRule,
            token_handler_common::csrf::require_header,
        ));
    // Outside the CSRF check, so refused requests are counted too.
    #[cfg(feature = "metrics")]
    let app = app.layer(middleware::from_fn(metrics::track));
    let app = app
        // Outermost, so even requests the CSRF check refuses get an id.
        .layer(middleware::from_fn(
            token_handler_common::request_id::middleware,
        ))
        .with_state(state.clone());

    let listen_addr = env::parsed_or(
        "LISTEN_ADDR",
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 5100)),
    )?;
    let listener = TcpListener::bind(listen_addr).await?;
    let config = &state.oidc.config;
    info!(
        issuer = %config.issuer,
        provider = config.provider.setting(),
        client_id = %config.client_id,
        client_credentials = config.client_credentials.method(),
        scopes = %config.scopes,
        redirect_uri = %config.redirect_uri,
        internal_endpoint = internal::enabled()?,
        "OAuth agent configured"
    );
    #[cfg(feature = "rate-limit")]
    info!(
        per_minute = state.login_per_minute,
        client_address = %state.client_ip,
        "sign-in rate limit"
    );
    info!("Listening on {}", listener.local_addr()?);

    // The OAuth proxy's way to a fresh access token: plain HTTP, so only where the service mesh
    // encrypts the link and admits only the proxy (see internal.rs).
    if internal::enabled()? {
        let internal_addr = env::parsed_or(
            "INTERNAL_ADDR",
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 5101)),
        )?;
        // Keeps the proxy's request id, so a refresh logs under the API call that needed it.
        let internal = internal::routes()
            .with_state(state.clone())
            .layer(middleware::from_fn(
                token_handler_common::request_id::middleware,
            ));
        let listener = TcpListener::bind(internal_addr).await?;
        info!("Internal endpoint on {}", listener.local_addr()?);
        tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, internal).await {
                error!(%error, "internal endpoint stopped");
            }
        });
    }

    #[cfg(feature = "metrics")]
    {
        let metrics_addr = env::parsed_or(
            "METRICS_ADDR",
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 9100)),
        )?;
        tokio::spawn(metrics::serve(metrics_addr));
    }

    // The peer address is the client IP for rate limiting, unless it is a
    // trusted proxy that names the client in its header.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(token_handler_common::shutdown::signal())
    .await?;
    Ok(())
}
