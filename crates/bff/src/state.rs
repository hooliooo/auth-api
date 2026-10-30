use std::sync::Arc;

use oidc::{OidcVerifier, ProviderClaims, VerificationError, well_known::Transport};
use redis::aio::ConnectionManager;
use reqwest::{Client, Url};
use serde_json::Value;

use crate::{
    client::{self, credentials::ClientAssertionError, ip::ClientIpSource},
    env,
    error::StartupError,
    identity_provider::IdentityProvider,
};

#[derive(Clone)]
pub(crate) struct AppState {
    /// Client for identity provider calls, with a short total timeout.
    pub http: Client,
    /// Shared Redis connection; reconnects on its own.
    pub redis: ConnectionManager,
    /// The identity provider: endpoints, client settings and token verifier.
    pub oidc: Arc<Oidc>,
    /// Client for API calls: bounded only while connecting and between bytes, never in total,
    /// so long responses stream through. Separate from [`Self::http`], whose calls must fail
    /// fast, and with its own connection pool.
    pub api_http: Client,
    /// `API_BASE_URL`: where `/api/*` is forwarded; `None` answers those requests with an error
    /// instead of refusing to start.
    pub api_base_url: Option<Arc<str>>,
    /// Where a request's client address comes from: the connection, or a trusted proxy's header
    /// (behind the ingress, its `x-real-ip`).
    pub client_ip: ClientIpSource,
}

impl AppState {
    /// The BFF's client id at the identity provider.
    pub fn client_id(&self) -> &str {
        &self.oidc.config.client_id
    }

    /// The form fields that authenticate the BFF on a call to the identity provider: its client
    /// id and its secret, or a fresh signed assertion addressed to the issuer.
    pub fn client_credentials_fields(
        &self,
    ) -> Result<Vec<(&'static str, String)>, ClientAssertionError> {
        let config = &self.oidc.config;
        config
            .client_credentials
            .form_fields(&config.client_id, &config.issuer)
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

    fn claims(payload: Value) -> Result<Self::Claims, VerificationError> {
        Ok(payload)
    }
}

/// The identity provider as the BFF uses it, resolved once at startup.
pub(crate) struct Oidc {
    /// The settings it was built from.
    pub config: OidcConfig,
    /// Verifies ID and logout tokens against the provider's keys.
    pub verifier: OidcVerifier<RawPayload>,
    /// The BFF's public origin, e.g. `https://app.example.com/`; derived from the redirect URI.
    pub public_base_url: Url,
    /// Where the browser signs in.
    pub authorization_url: Url,
    /// Where the browser signs out of the provider, if it publishes such a page.
    pub end_session_url: Option<Url>,
}

impl Oidc {
    /// Reads the provider's discovery document and keys with `http`, as `config` says; waits for
    /// a provider that is still starting.
    pub async fn discover(http: Client, config: OidcConfig) -> Result<Self, StartupError> {
        // The issuer is also where the BFF reaches the provider: one address for browsers and
        // services (in the cluster, the public name resolves to the ingress inside it too).
        let verifier = OidcVerifier::<RawPayload>::new(
            &config.issuer,
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

        let end_session_url = well_known
            .end_session_endpoint
            .as_deref()
            .map(Url::parse)
            .transpose()
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

    /// Where a provider session ends at logout: the BFF's own server-to-server call and the
    /// browser use the same endpoint.
    pub fn end_session_endpoint(&self) -> Option<&str> {
        self.verifier.end_session_endpoint()
    }

    /// Where the BFF revokes a refresh token at logout.
    pub fn revocation_endpoint(&self) -> Option<&str> {
        self.verifier.revocation_endpoint()
    }
}

/// Identity provider settings, read from the environment.
#[derive(Clone)]
pub(crate) struct OidcConfig {
    /// `ISSUER_URI`: the issuer tokens name, and where the BFF reaches the provider.
    pub issuer: String,
    /// `CLIENT_ID`.
    pub client_id: String,
    /// How the BFF authenticates itself: `CLIENT_AUTH` and its keys or secret.
    pub client_credentials: client::credentials::Credentials,
    /// `REDIRECT_URI`: the BFF's public sign-in callback.
    pub redirect_uri: String,
    /// Whether `http://` URLs are accepted for the provider and the BFF's own redirect URI.
    pub transport: Transport,
    /// `OIDC_SCOPES`: the scopes every sign-in requests, space-separated; never the browser's
    /// choice.
    pub scopes: String,
    /// `IDENTITY_PROVIDER`: what the provider adds to, or leaves out of, the standards.
    pub provider: IdentityProvider,
}

impl OidcConfig {
    /// Reads and validates the settings; HTTP URLs only with `ALLOW_INSECURE_HTTP=true`, and
    /// scopes as [`scopes_from`] allows.
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
            scopes: scopes_from(std::env::var("OIDC_SCOPES").ok().as_deref())?,
            issuer,
            client_id: env::env("CLIENT_ID")?,
            client_credentials: client::credentials::Credentials::from_env()?,
            redirect_uri,
            provider: IdentityProvider::from_env()?,
        })
    }
}

/// The scopes to request, from the `OIDC_SCOPES` value `setting` (default `openid`): must
/// include `openid`, and never `offline_access`, whose refresh tokens are made to outlive the
/// session they came from.
fn scopes_from(setting: Option<&str>) -> Result<String, StartupError> {
    let scopes: Vec<&str> = setting.unwrap_or("openid").split_whitespace().collect();
    if !scopes.contains(&"openid") {
        return Err(StartupError::InvalidScopes("they must include openid"));
    }
    if scopes.contains(&"offline_access") {
        return Err(StartupError::InvalidScopes(
            "offline_access is refused: sessions end with the provider's",
        ));
    }
    Ok(scopes.join(" "))
}
