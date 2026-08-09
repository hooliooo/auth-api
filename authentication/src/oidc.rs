use std::marker::PhantomData;

use jsonwebtoken::{DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::Deserialize;
use serde_json::Value;

use crate::{
    error::JwtVerificationError,
    verifier::{ClaimsExtractor, JwtVerifier},
};

/// The path OIDC Discovery 1.0 mandates for the document, relative to the issuer.
const DISCOVERY_PATH: &str = ".well-known/openid-configuration";

/// How a provider's claims type is built from a verified token's payload.
///
/// This is the only thing that differs between providers, so it is what
/// [`OidcJwtVerifier`] is parameterised by.
pub trait ProviderClaims: ClaimsExtractor + 'static {
    fn from_payload(payload: Value) -> Self;
}

/// Verifies tokens against an OpenID Connect provider: signature via the provider's JWKS, plus
/// audience, issuer and expiry.
///
/// All of that is defined by OIDC, so it is identical for every compliant provider — `C`
/// supplies the only provider-specific part, reading the payload into [`Claims`](crate::Claims).
#[derive(Clone, Debug)]
pub struct OidcJwtVerifier<C> {
    well_known_endpoint: WellKnownEndpoint,
    client: reqwest::Client,
    audience: String,
    validate_expiration: bool,
    _marker: PhantomData<fn() -> C>,
}

impl<C> OidcJwtVerifier<C> {
    /// `issuer_url` is the provider's base URL, e.g.
    /// `https://keycloak.example.com/realms/some-realm`.
    pub async fn new(
        issuer_url: &str,
        client: reqwest::Client,
        audience: String,
        validate_expiration: bool,
    ) -> Result<Self, WellKnownEndpointError> {
        let well_known_endpoint = WellKnownEndpoint::fetch(&client, issuer_url).await?;

        Ok(Self {
            well_known_endpoint,
            client,
            audience,
            validate_expiration,
            _marker: PhantomData,
        })
    }

    pub fn token_endpoint(&self) -> &str {
        &self.well_known_endpoint.token_endpoint
    }

    fn jwks_uri(&self) -> &str {
        &self.well_known_endpoint.jwks_uri
    }

    /// Verifies `raw_token` and returns its payload untouched.
    async fn verify_payload(&self, raw_token: &str) -> Result<Value, JwtVerificationError> {
        let header = decode_header(raw_token).map_err(|_| JwtVerificationError::InvalidJwt)?;

        // The key id selects which JWK signed this token; without one there is nothing to look up.
        let kid = header.kid.ok_or(JwtVerificationError::InvalidJwt)?;

        let jwk_set: JwkSet = self
            .client
            .get(self.jwks_uri())
            .send()
            .await
            .map_err(|_| JwtVerificationError::CertsUrlInvalid)?
            .json()
            .await
            .map_err(|_| JwtVerificationError::CertsUrlInvalid)?;

        let jwk = jwk_set
            .find(&kid)
            .ok_or(JwtVerificationError::JwkNotFound)?;

        let decoding_key =
            DecodingKey::from_jwk(jwk).map_err(|_| JwtVerificationError::InvalidJwk)?;

        let validation = {
            let mut validation = Validation::new(header.alg);
            validation.set_audience(&[self.audience.as_str()]);
            validation.set_issuer(&[self.well_known_endpoint.issuer.as_str()]);
            validation.validate_exp = self.validate_expiration;
            validation
        };

        decode::<Value>(raw_token, &decoding_key, &validation)
            .map(|token| token.claims)
            .map_err(|error| {
                JwtVerificationError::ValidationError(format!("{:?}", error.into_kind()))
            })
    }
}

#[async_trait::async_trait]
impl<C: ProviderClaims> JwtVerifier for OidcJwtVerifier<C> {
    async fn verify(
        &self,
        raw_token: &str,
    ) -> Result<Box<dyn ClaimsExtractor>, JwtVerificationError> {
        let payload = self.verify_payload(raw_token).await?;
        Ok(Box::new(C::from_payload(payload)))
    }
}

/// The discovery document served from `/.well-known/openid-configuration`.
#[derive(Clone, Debug, Deserialize)]
pub struct WellKnownEndpoint {
    pub issuer: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
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
#[derive(Debug)]
pub enum WellKnownEndpointError {
    Unreachable(reqwest::Error),
    ErrorStatus(reqwest::Error),
    Malformed(reqwest::Error),
}

impl std::fmt::Display for WellKnownEndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(error) => {
                write!(f, "Could not reach the well-known endpoint: {}", error)
            }
            Self::ErrorStatus(error) => {
                write!(f, "The well-known endpoint returned an error: {}", error)
            }
            Self::Malformed(error) => {
                write!(f, "The well-known endpoint is not valid JSON: {}", error)
            }
        }
    }
}

impl std::error::Error for WellKnownEndpointError {}
