use std::{sync::Arc, time::Duration};

use axum::Router;
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
mod env;
mod error;
mod pkce;
mod random;
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

    let state = AppState {
        http: client,
        oidc: Arc::new(oidc),
        redis,
    };

    let app = Router::new().merge(auth::routes()).with_state(state);
    let listener = TcpListener::bind("0.0.0.0:5100").await?;
    info!("Listening on {}", listener.local_addr()?);

    axum::serve(listener, app).await?;
    Ok(())
}
