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

/// Allowed clock difference with the provider when checking `exp`, `nbf` and `iat`.
pub const LEEWAY_SECS: u64 = 30;

/// Claims every accepted token must carry. jsonwebtoken only checks `aud` and `iss` when they
/// are present, so without this a token that simply leaves `aud` out passes the audience check.
/// `sub` is not listed: a back-channel logout token may carry only `sid`. jsonwebtoken cannot
/// require `iat`, so [`OidcJwtVerifier::verify_payload`] checks it.
const REQUIRED_CLAIMS: [&str; 3] = ["exp", "iss", "aud"];

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
        Ok(Self::from_parts(well_known_endpoint, keys, &audience))
    }

    /// Assembles a verifier from an already loaded discovery document and key cache.
    fn from_parts(well_known_endpoint: WellKnownEndpoint, keys: Cache, audience: &str) -> Self {
        let validations = ALGORITHMS
            .into_iter()
            .map(|algorithm| {
                let mut validation = Validation::new(algorithm);
                validation.set_audience(&[audience]);
                validation.set_issuer(&[well_known_endpoint.issuer.as_str()]);
                validation.set_required_spec_claims(&REQUIRED_CLAIMS);
                validation.validate_nbf = true;
                validation.leeway = LEEWAY_SECS;
                (algorithm, validation)
            })
            .collect();
        Self {
            well_known_endpoint,
            keys: Arc::new(keys),
            validations,
            _marker: PhantomData,
        }
    }

    pub fn well_known_endpoint(&self) -> &WellKnownEndpoint {
        &self.well_known_endpoint
    }

    pub fn token_endpoint(&self) -> &str {
        &self.well_known_endpoint.token_endpoint
    }

    pub fn revocation_endpoint(&self) -> &str {
        &self.well_known_endpoint.revocation_endpoint
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

        let payload = decode::<Value>(raw_token, &key.key, validation)
            .map(|token| token.claims)
            .map_err(|error| JwtVerificationError::Invalid(format!("{:?}", error.into_kind())))?;
        check_issued_at(&payload)?;
        Ok(payload)
    }
}

/// `iat` must be present and not in the future: a token "issued" later than now was not made
/// by a provider whose clock agrees with ours.
fn check_issued_at(payload: &Value) -> Result<(), JwtVerificationError> {
    let iat = payload
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or(JwtVerificationError::MissingClaim("iat"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    if iat > now + LEEWAY_SECS {
        return Err(JwtVerificationError::Invalid(
            "token issued in the future".to_string(),
        ));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use async_trait::async_trait;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::jwk::JwkSet;
    use ring::{
        hmac,
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use serde_json::{Value, json};

    use super::*;
    use crate::cache::{Cache, JwksSource, SourceError};

    const ISSUER: &str = "https://idp.example/realms/test";
    const AUDIENCE: &str = "api";

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn encode(value: &Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap())
    }

    /// A signing key generated per test, published under `kid`.
    struct TestKey {
        kid: &'static str,
        pair: Ed25519KeyPair,
    }

    impl TestKey {
        fn new(kid: &'static str) -> Self {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            Self {
                kid,
                pair: Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap(),
            }
        }

        fn jwk(&self) -> Value {
            json!({
                "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": self.kid,
                "x": URL_SAFE_NO_PAD.encode(self.pair.public_key().as_ref()),
            })
        }

        fn sign(&self, header: &Value, claims: &Value) -> String {
            let input = format!("{}.{}", encode(header), encode(claims));
            let signature = self.pair.sign(input.as_bytes());
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
        }

        fn token(&self, claims: &Value) -> String {
            self.sign(
                &json!({ "alg": "EdDSA", "typ": "JWT", "kid": self.kid }),
                claims,
            )
        }
    }

    #[derive(Debug)]
    struct StaticSource(JwkSet);

    #[async_trait]
    impl JwksSource for StaticSource {
        async fn fetch(&self) -> Result<JwkSet, SourceError> {
            Ok(self.0.clone())
        }
    }

    struct Raw;

    impl ProviderClaims for Raw {
        type Claims = Value;
        fn claims(payload: Value) -> Result<Value, JwtVerificationError> {
            Ok(payload)
        }
    }

    async fn verifier(published: &[&TestKey]) -> OidcJwtVerifier<Raw> {
        let keys: Vec<Value> = published.iter().map(|key| key.jwk()).collect();
        let set: JwkSet = serde_json::from_value(json!({ "keys": keys })).unwrap();
        let cache = Cache::new(StaticSource(set), KEY_TTL, KEY_MIN_REFRESH_INTERVAL)
            .await
            .unwrap();
        let endpoint = |path: &str| format!("{ISSUER}/{path}");
        let well_known = WellKnownEndpoint {
            issuer: ISSUER.to_owned(),
            authorization_endpoint: endpoint("auth"),
            token_endpoint: endpoint("token"),
            end_session_endpoint: endpoint("logout"),
            jwks_uri: endpoint("certs"),
            revocation_endpoint: endpoint("revoke"),
        };
        OidcJwtVerifier::from_parts(well_known, cache, AUDIENCE)
    }

    fn claims() -> Value {
        let now = now();
        json!({ "iss": ISSUER, "aud": AUDIENCE, "sub": "user-1", "iat": now, "exp": now + 300 })
    }

    fn without(claim: &str) -> Value {
        let mut claims = claims();
        claims.as_object_mut().unwrap().remove(claim);
        claims
    }

    fn with(claim: &str, value: Value) -> Value {
        let mut claims = claims();
        claims[claim] = value;
        claims
    }

    async fn assert_refused(verifier: &OidcJwtVerifier<Raw>, token: &str, why: &str) {
        let result = verifier.verify(token).await;
        assert!(
            matches!(result, Err(JwtVerificationError::Invalid(_))),
            "{why}: {result:?}"
        );
    }

    #[tokio::test]
    async fn given_a_valid_token_then_its_payload_is_returned() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        let payload = verifier.verify(&key.token(&claims())).await.unwrap();
        assert_eq!(payload["sub"], "user-1");
    }

    #[tokio::test]
    async fn given_a_missing_or_wrong_audience_then_it_is_refused() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        assert_refused(&verifier, &key.token(&without("aud")), "no aud").await;
        assert_refused(
            &verifier,
            &key.token(&with("aud", json!("other"))),
            "other aud",
        )
        .await;
    }

    #[tokio::test]
    async fn given_a_missing_or_wrong_issuer_then_it_is_refused() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        assert_refused(&verifier, &key.token(&without("iss")), "no iss").await;
        let other = with("iss", json!("https://evil.example/realms/test"));
        assert_refused(&verifier, &key.token(&other), "other iss").await;
    }

    #[tokio::test]
    async fn given_a_missing_iat_or_exp_then_it_is_refused() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        assert!(matches!(
            verifier.verify(&key.token(&without("iat"))).await,
            Err(JwtVerificationError::MissingClaim("iat"))
        ));
        assert_refused(&verifier, &key.token(&without("exp")), "no exp").await;
        let future = with("iat", json!(now() + LEEWAY_SECS + 60));
        assert_refused(&verifier, &key.token(&future), "iat in the future").await;
    }

    #[tokio::test]
    async fn given_an_expired_token_then_only_the_leeway_is_tolerated() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        let just_expired = with("exp", json!(now() - LEEWAY_SECS / 2));
        assert!(verifier.verify(&key.token(&just_expired)).await.is_ok());
        let expired = with("exp", json!(now() - LEEWAY_SECS - 5));
        assert_refused(&verifier, &key.token(&expired), "expired").await;
    }

    #[tokio::test]
    async fn given_a_token_that_is_not_valid_yet_then_it_is_refused() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        let future = with("nbf", json!(now() + LEEWAY_SECS + 60));
        assert_refused(&verifier, &key.token(&future), "nbf in the future").await;
    }

    #[tokio::test]
    async fn given_alg_none_then_it_is_refused() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        let header = encode(&json!({ "alg": "none", "kid": "k1" }));
        let token = format!("{header}.{}.", encode(&claims()));
        assert_refused(&verifier, &token, "alg none").await;
    }

    /// The classic key-confusion attack: an HMAC signature keyed with the public key.
    #[tokio::test]
    async fn given_hs256_signed_with_the_public_key_then_it_is_refused() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        let input = format!(
            "{}.{}",
            encode(&json!({ "alg": "HS256", "typ": "JWT", "kid": "k1" })),
            encode(&claims())
        );
        let mac = hmac::Key::new(hmac::HMAC_SHA256, key.pair.public_key().as_ref());
        let signature = hmac::sign(&mac, input.as_bytes());
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()));
        assert_refused(&verifier, &token, "HS256 with the public key").await;
    }

    #[tokio::test]
    async fn given_a_signature_by_another_key_then_it_is_refused() {
        let published = TestKey::new("k1");
        let attacker = TestKey::new("k1");
        let verifier = verifier(&[&published]).await;
        assert_refused(
            &verifier,
            &attacker.token(&claims()),
            "foreign key, same kid",
        )
        .await;
    }

    #[tokio::test]
    async fn given_no_or_an_unknown_key_id_then_it_is_refused() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        let no_kid = key.sign(&json!({ "alg": "EdDSA" }), &claims());
        assert_refused(&verifier, &no_kid, "no kid").await;
        let unknown = TestKey::new("k2");
        assert_refused(&verifier, &unknown.token(&claims()), "unknown kid").await;
    }

    #[tokio::test]
    async fn given_a_tampered_payload_then_it_is_refused() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        let token = key.token(&claims());
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = encode(&with("sub", json!("admin")));
        parts[1] = &forged;
        assert_refused(&verifier, &parts.join("."), "tampered payload").await;
    }
}
