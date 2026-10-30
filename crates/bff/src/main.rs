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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
