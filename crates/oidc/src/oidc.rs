//! Verification shared by every OpenID Connect provider: discovery, signature checks against
//! the provider's JWKS, and the audience, issuer and expiry validations.

use std::{collections::HashMap, marker::PhantomData, sync::Arc, time::Duration};

use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use crate::cache::{Cache, HttpJwksSource, SourceError};

/// The path OIDC Discovery 1.0 mandates for the document, relative to the issuer.
const DISCOVERY_PATH: &str = ".well-known/openid-configuration";

/// How long fetched signing keys are trusted before they are refreshed.
const KEY_TTL: Duration = Duration::from_secs(10 * 60);

/// The minimum time between two refetch attempts.
const KEY_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// The asymmetric algorithms a signing key may use. Which one applies to a token is decided
/// by the key that signed it, never by the token's own header.
///
/// A policy rather than configuration: discovery documents only describe ID tokens, and list
/// every algorithm a provider implements, symmetric ones included. ES512 is absent because
/// jsonwebtoken does not support P-521 keys.
const ALGORITHMS: [Algorithm; 9] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// The claims this service acts on, read from a verified token.
/// Values keep the provider's own format, e.g. `user_id` is whatever the provider uses as
/// the subject.
#[derive(Clone, Debug)]
pub struct StandardClaims {
    pub azp: String,
    pub sub: String,
}

/// Verifies a raw bearer token against an identity provider and reads its claims.
#[async_trait::async_trait]
pub trait JwtVerifier: Send + Sync {
    type Claims;
    async fn verify(&self, raw_token: &str) -> Result<Self::Claims, JwtVerificationError>;
}

/// Why a token was not accepted, in terms the application can act on. Adapters map their
/// provider's failures onto these and put the specifics in the message.
#[derive(Debug, Error)]
pub enum JwtVerificationError {
    /// The token is malformed, forged, expired or meant for another audience
    #[error("Invalid token: {0}")]
    Invalid(String),
    /// The identity provider could not be reached to verify the token
    #[error("Identity provider unavailable: {0}")]
    ProviderUnavailable(String),
    /// A verified token lacks a claim this service needs
    #[error("Missing claim: {0}")]
    MissingClaim(&'static str),
}

/// How a provider's token payload is read into the [`Claims`] this service acts on.
///
/// This is the only thing that differs between providers, so it is what
/// [`OidcJwtVerifier`] is parameterised by.
pub trait ProviderClaims {
    type Claims;
    fn claims(payload: Value) -> Result<Self::Claims, JwtVerificationError>;
}

/// Verifies tokens against an OpenID Connect provider: signature via the provider's JWKS, plus
/// audience, issuer and expiry.
///
/// All of that is defined by OIDC, so it is identical for every compliant provider — `C`
/// supplies the only provider-specific part, reading the payload into [`Claims`].
pub struct OidcJwtVerifier<P> {
    well_known_endpoint: WellKnownEndpoint,
    keys: Arc<Cache>,
    /// One per algorithm, built once: the audience and issuer never change after startup.
    validations: HashMap<Algorithm, Validation>,
    _marker: PhantomData<fn() -> P>,
}

impl<P> OidcJwtVerifier<P> {
    pub async fn new(
        issuer_url: &str,
        client: reqwest::Client,
        audience: String,
    ) -> Result<Self, OidcSetupError> {
        Self::with_discovery_url(issuer_url, issuer_url, client, audience).await
    }

    /// `issuer_url` is the provider's base URL, e.g.
    /// `https://keycloak.example.com/realms/some-realm`. Reads the discovery document and the
    /// signing keys, so it fails if the provider cannot be reached.
    pub async fn with_discovery_url(
        issuer_url: &str,
        discovery_url: &str,
        client: reqwest::Client,
        audience: String,
    ) -> Result<Self, OidcSetupError> {
        let well_known_endpoint = WellKnownEndpoint::fetch(&client, discovery_url).await?;

        // OIDC Discovery 1.0 §4.3: the document must name the issuer it was fetched for,
        // otherwise the endpoint, not this configuration, decides which tokens are accepted.
        if well_known_endpoint.issuer.trim_end_matches('/') != issuer_url.trim_end_matches('/') {
            return Err(OidcSetupError::IssuerMismatch {
                expected: issuer_url.to_owned(),
                found: well_known_endpoint.issuer,
            });
        }

        let source = HttpJwksSource::new(client, well_known_endpoint.jwks_uri.clone());
        let keys = Cache::new(source, KEY_TTL, KEY_MIN_REFRESH_INTERVAL).await?;

        let validations = ALGORITHMS
            .into_iter()
            .map(|algorithm| {
                let mut validation = Validation::new(algorithm);
                validation.set_audience(&[audience.as_str()]);
                validation.set_issuer(&[well_known_endpoint.issuer.as_str()]);
                (algorithm, validation)
            })
            .collect();
        Ok(Self {
            well_known_endpoint,
            keys: Arc::new(keys),
            validations,
            _marker: PhantomData,
        })
    }

    pub fn well_known_endpoint(&self) -> &WellKnownEndpoint {
        &self.well_known_endpoint
    }

    pub fn token_endpoint(&self) -> &str {
        &self.well_known_endpoint.token_endpoint
    }

    /// Verifies `raw_token` and returns its payload untouched.
    ///
    /// Only an unreachable provider is not the token's fault; every other failure means the
    /// token cannot be trusted, so it is reported as invalid with the specific reason.
    async fn verify_payload(&self, raw_token: &str) -> Result<Value, JwtVerificationError> {
        let header = decode_header(raw_token)
            .map_err(|_| JwtVerificationError::Invalid("malformed token header".to_string()))?;

        // The key id selects which JWK signed this token; without one there is nothing to look up.
        let kid = header
            .kid
            .ok_or_else(|| JwtVerificationError::Invalid("token has no key id".to_string()))?;

        let key = self.keys.key(&kid).await?;
        if header.alg != key.algorithm {
            return Err(JwtVerificationError::Invalid(format!(
                "key '{kid}' signs with {:?}, not {:?}",
                key.algorithm, header.alg
            )));
        }
        let validation = self.validations.get(&key.algorithm).ok_or_else(|| {
            JwtVerificationError::Invalid(format!("unsupported algorithm {:?}", header.alg))
        })?;

        decode::<Value>(raw_token, &key.key, validation)
            .map(|token| token.claims)
            .map_err(|error| JwtVerificationError::Invalid(format!("{:?}", error.into_kind())))
    }
}

#[async_trait::async_trait]
impl<P: ProviderClaims> JwtVerifier for OidcJwtVerifier<P>
where
    P::Claims: Send,
{
    type Claims = P::Claims;
    async fn verify(&self, raw_token: &str) -> Result<P::Claims, JwtVerificationError> {
        let payload = self.verify_payload(raw_token).await?;
        P::claims(payload)
    }
}

/// The discovery document served from `/.well-known/openid-configuration`.
#[derive(Clone, Debug, Deserialize)]
pub struct WellKnownEndpoint {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub end_session_endpoint: String,
    pub jwks_uri: String,
    pub revocation_endpoint: String,
}

impl WellKnownEndpoint {
    /// Reads the discovery document for `issuer_url`, e.g.
    /// `https://keycloak.example.com/realms/some-realm`. The well-known path is appended here
    /// rather than by the caller, since the specification fixes it.
    pub async fn fetch(
        client: &reqwest::Client,
        issuer_url: &str,
    ) -> Result<Self, WellKnownEndpointError> {
        let url = format!("{}/{}", issuer_url.trim_end_matches('/'), DISCOVERY_PATH);

        client
            .get(url)
            .send()
            .await
            .map_err(WellKnownEndpointError::Unreachable)?
            .error_for_status()
            .map_err(WellKnownEndpointError::ErrorStatus)?
            .json()
            .await
            .map_err(WellKnownEndpointError::Malformed)
    }
}

/// A failure reading the discovery document at startup.
#[derive(Debug, Error)]
pub enum WellKnownEndpointError {
    #[error("Could not reach the well-known endpoint: {0}")]
    Unreachable(reqwest::Error),
    #[error("The well-known endpoint returned an error: {0}")]
    ErrorStatus(reqwest::Error),
    #[error("The well-known endpoint is not valid JSON: {0}")]
    Malformed(reqwest::Error),
}

/// A failure setting up the verifier during startup.
#[derive(Debug, Error)]
pub enum OidcSetupError {
    #[error(transparent)]
    Discovery(#[from] WellKnownEndpointError),
    #[error("The discovery document is for issuer '{found}', not '{expected}'")]
    IssuerMismatch { expected: String, found: String },
    #[error("Could not load the signing keys: {0}")]
    SigningKeys(#[from] SourceError),
}
