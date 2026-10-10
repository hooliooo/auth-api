use oidc::{OidcJwtVerifier, ProviderClaims};
use redis::aio::ConnectionManager;
use reqwest::{Client, Url};
use serde_json::Value;
use std::sync::Arc;

use crate::{env, error::StartupError};

#[derive(Clone)]
pub(crate) struct AppState {
    pub http: Client,
    pub api_http: Client,
    pub oidc: Arc<Oidc>,
    pub redis: ConnectionManager,
    pub api_base_url: Option<Arc<str>>,
}

impl AppState {
    pub fn client_id(&self) -> &str {
        &self.oidc.config.client_id
    }

    pub fn client_secret(&self) -> &str {
        &self.oidc.config.client_secret
    }

    pub fn redirect_uri(&self) -> &str {
        &self.oidc.config.redirect_uri
    }

    pub fn authorization_endpoint(&self) -> &str {
        self.oidc.authorization_url.as_str()
    }
}

pub(crate) struct RawPayload;

impl ProviderClaims for RawPayload {
    type Claims = Value;

    fn claims(
        payload: serde_json::Value,
    ) -> Result<Self::Claims, oidc::oidc::JwtVerificationError> {
        Ok(payload)
    }
}

pub(crate) struct Oidc {
    pub config: OidcConfig,
    pub verifier: OidcJwtVerifier<RawPayload>,
    pub public_base_url: Url,
    pub authorization_url: Url,
    pub end_session_url: Url,
}

impl Oidc {
    pub async fn discover(http: Client, config: OidcConfig) -> Result<Self, StartupError> {
        let verifier: OidcJwtVerifier<RawPayload> = OidcJwtVerifier::with_discovery_url(
            &config.issuer,
            &config.discover_url,
            http,
            config.client_id.clone(),
        )
        .await?;

        let public_base_url = Url::parse(&config.redirect_uri)
            .and_then(|u| u.join("/"))
            .map_err(|_| StartupError::InvalidUrl("redirect_uri"))?;

        let well_known = verifier.well_known_endpoint();
        let authorization_url = Url::parse(&well_known.authorization_endpoint)
            .map_err(|_| StartupError::InvalidUrl("authorization_url"))?;

        let end_session_url = Url::parse(&well_known.end_session_endpoint)
            .map_err(|_| StartupError::InvalidUrl("end_session_url"))?;
        Ok(Self {
            config,
            verifier,
            public_base_url,
            authorization_url,
            end_session_url,
        })
    }

    pub fn token_endpoint(&self) -> &str {
        self.verifier.token_endpoint()
    }

    pub fn revocation_endpoint(&self) -> &str {
        self.verifier.revocation_endpoint()
    }
}

#[derive(Clone)]
pub(crate) struct OidcConfig {
    pub issuer: String,
    pub discover_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

impl OidcConfig {
    pub fn from_env() -> Result<Self, StartupError> {
        let issuer = env::env("ISSUER_URI")?;
        Ok(OidcConfig {
            discover_url: env::env("DISCOVERY_URI").unwrap_or_else(|_| issuer.clone()),
            issuer,
            client_id: env::env("CLIENT_ID")?,
            client_secret: env::env("CLIENT_SECRET")?,
            redirect_uri: env::env("REDIRECT_URI")?,
        })
    }
}
