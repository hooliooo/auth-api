use std::{sync::Arc, time::Duration};

use axum::{Router, middleware};
use reqwest::{Client, redirect};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::{
    random::random_token,
    state::{AppState, Oidc, OidcConfig},
};

mod auth;
mod cookie;
mod crypto;
mod csrf;
mod env;
mod error;
mod health;
mod pkce;
mod proxy;
mod random;
mod sealed;
mod session;
mod state;

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

    let state = AppState {
        http: client,
        oidc: Arc::new(oidc),
        redis,
        api_base_url: api_base_url.map(Arc::from),
    };

    let app = Router::new()
        .merge(auth::routes())
        .merge(proxy::routes())
        .merge(health::routes())
        .layer(middleware::from_fn(csrf::require_header))
        .with_state(state);
    let listener = TcpListener::bind("0.0.0.0:5100").await?;
    info!("Listening on {}", listener.local_addr()?);

    axum::serve(listener, app).await?;
    Ok(())
}
