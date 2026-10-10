//! Shared application state and the OpenID Connect configuration.

use crate::client_ip::ClientIpSource;
use oidc::{OidcJwtVerifier, ProviderClaims, Transport};
use redis::aio::ConnectionManager;
use reqwest::{Client, Url};
use serde_json::Value;
use std::sync::Arc;

use crate::{env, error::StartupError};

/// Everything a request handler needs; cheap to clone.
#[derive(Clone)]
pub(crate) struct AppState {
    /// Client for identity provider calls, with a short total timeout.
    pub http: Client,
    /// Client for API calls, without a total timeout so long responses stream.
    pub api_http: Client,
    /// The identity provider: endpoints, client settings and token verifier.
    pub oidc: Arc<Oidc>,
    /// Shared Redis connection; reconnects on its own.
    pub redis: ConnectionManager,
    /// Where `/api/*` is forwarded; `None` disables the proxy.
    pub api_base_url: Option<Arc<str>>,
    /// Where client addresses come from: the connection, or a trusted proxy's header.
    pub client_ip: ClientIpSource,
    /// Sign-in starts allowed per client IP and minute; 0 turns the limit off.
    #[cfg(feature = "rate-limit")]
    pub login_per_minute: u32,
}

impl AppState {
    /// The BFF's client id at the identity provider.
    pub fn client_id(&self) -> &str {
        &self.oidc.config.client_id
    }

    /// The BFF's client secret at the identity provider.
    pub fn client_secret(&self) -> &str {
        &self.oidc.config.client_secret
    }

    /// The BFF's public sign-in callback URL.
    pub fn redirect_uri(&self) -> &str {
        &self.oidc.config.redirect_uri
    }

    /// Where the browser is sent to sign in.
    pub fn authorization_endpoint(&self) -> &str {
        self.oidc.authorization_url.as_str()
    }
}

/// Hands verified token payloads back untouched; the BFF reads the claims it needs itself.
pub(crate) struct RawPayload;

impl ProviderClaims for RawPayload {
    type Claims = Value;

    fn claims(
        payload: serde_json::Value,
    ) -> Result<Self::Claims, oidc::oidc::JwtVerificationError> {
        Ok(payload)
    }
}

/// The identity provider as the BFF uses it, resolved once at startup.
pub(crate) struct Oidc {
    /// The settings it was built from.
    pub config: OidcConfig,
    /// Verifies ID and logout tokens against the provider's keys.
    pub verifier: OidcJwtVerifier<RawPayload>,
    /// The BFF's public origin, e.g. `https://app.example.com/`; derived from the redirect URI.
    pub public_base_url: Url,
    /// Where the browser signs in.
    pub authorization_url: Url,
    /// Where the browser signs out of the provider.
    pub end_session_url: Url,
}

impl Oidc {
    /// Reads the provider's discovery document and keys with `http`, as `config` says.
    pub async fn discover(http: Client, config: OidcConfig) -> Result<Self, StartupError> {
        let verifier: OidcJwtVerifier<RawPayload> = OidcJwtVerifier::with_discovery_url(
            &config.issuer,
            &config.discover_url,
            http,
            config.client_id.clone(),
            config.transport,
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

    /// Where codes and refresh tokens are exchanged.
    pub fn token_endpoint(&self) -> &str {
        self.verifier.token_endpoint()
    }

    /// Where refresh tokens are revoked at logout.
    pub fn revocation_endpoint(&self) -> &str {
        self.verifier.revocation_endpoint()
    }
}

/// Identity provider settings, read from the environment.
#[derive(Clone)]
pub(crate) struct OidcConfig {
    /// `ISSUER_URI`: the issuer tokens name.
    pub issuer: String,
    /// `DISCOVERY_URI`: where the BFF itself reaches the provider; defaults to the issuer.
    pub discover_url: String,
    /// `CLIENT_ID`.
    pub client_id: String,
    /// `CLIENT_SECRET`.
    pub client_secret: String,
    /// `REDIRECT_URI`: the BFF's public sign-in callback.
    pub redirect_uri: String,
    /// Whether `http://` URLs are accepted for Keycloak and the BFF's own redirect URI.
    pub transport: Transport,
}

impl OidcConfig {
    /// Reads and validates the settings; HTTP URLs only with `ALLOW_INSECURE_HTTP=true`.
    pub fn from_env() -> Result<Self, StartupError> {
        let issuer = env::env("ISSUER_URI")?;
        // Plain HTTP only when explicitly allowed, for a local dev stack.
        let transport = match std::env::var("ALLOW_INSECURE_HTTP").as_deref() {
            Err(_) | Ok("false") => Transport::HttpsOnly,
            Ok("true") => Transport::AllowInsecureHttp,
            Ok(_) => return Err(StartupError::InvalidSetting("ALLOW_INSECURE_HTTP")),
        };
        let redirect_uri = env::env("REDIRECT_URI")?;
        // The session cookie is `__Host-` and `Secure`: browsers only keep it over HTTPS
        // (localhost aside), so an HTTP redirect URI is a dev-only setup too.
        if transport == Transport::HttpsOnly && !redirect_uri.starts_with("https://") {
            return Err(StartupError::InsecureRedirectUri);
        }
        Ok(OidcConfig {
            transport,
            discover_url: env::env("DISCOVERY_URI").unwrap_or_else(|_| issuer.clone()),
            issuer,
            client_id: env::env("CLIENT_ID")?,
            client_secret: env::env("CLIENT_SECRET")?,
            redirect_uri,
        })
    }
}
