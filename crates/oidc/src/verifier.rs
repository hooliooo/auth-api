//! Verifying tokens: [`OidcVerifier`] discovers the provider, loads its signing keys, and
//! checks each token's signature and claims; [`ProviderClaims`] reads what a service needs
//! from a verified payload.

use std::{collections::HashMap, marker::PhantomData, sync::Arc, time::Duration};

use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde_json::Value;
use thiserror::Error;

use crate::{
    jwks::{HttpJwksSource, JwksSourceError, cache::Cache},
    retry::{Backoff, retry_transient},
    well_known::{InsecureUrlError, Transport, WellKnownEndpoint, WellKnownEndpointError},
};

/// How long fetched signing keys are trusted before they are refreshed.
const KEY_TTL: Duration = Duration::from_secs(10 * 60);

/// The minimum time between two refetch attempts.
const KEY_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// How [`OidcVerifier::new`] retries a provider that cannot be reached yet, e.g. one still
/// starting next to this service: waits from half a second, doubling up to 10 seconds, for up to
/// two minutes in all. Configuration mistakes are never retried.
const STARTUP_BACKOFF: Backoff = Backoff {
    first: Duration::from_millis(500),
    max: Duration::from_secs(10),
    give_up_after: Duration::from_secs(120),
};

/// Allowed clock difference with the provider when checking `exp`, `nbf` and `iat`.
pub const LEEWAY_SECS: u64 = 30;

/// Claims every accepted token must carry. jsonwebtoken only checks `aud` and `iss` when they
/// are present, so without this a token that simply leaves `aud` out passes the audience check.
/// `sub` is not listed: a back-channel logout token may carry only `sid`. jsonwebtoken cannot
/// require `iat`, so [`OidcVerifier::verify_payload`] checks it.
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

/// Why a token was not accepted, in terms the application can act on. Adapters map their
/// provider's failures onto these and put the specifics in the message.
#[derive(Debug, Error)]
pub enum VerificationError {
    /// The token is malformed, forged, expired or meant for another audience
    #[error("Invalid token: {0}")]
    Invalid(String),
    /// A verified token lacks a claim this service needs
    #[error("Missing claim: {0}")]
    MissingClaim(&'static str),
    /// The identity provider could not be reached to verify the token
    #[error("Identity provider unavailable: {0}")]
    ProviderUnavailable(String),
}

/// Verifies a raw bearer token against an identity provider and reads its claims.
#[async_trait::async_trait]
pub trait Verifier: Send + Sync {
    /// What a verified token is read into.
    type Claims;
    /// Verifies `raw_token` and reads its claims.
    async fn verify(&self, raw_token: &str) -> Result<Self::Claims, VerificationError>;
}

/// How a provider's token payload is read into the claims a service acts on: the only thing
/// that differs between providers, so it is what [`OidcVerifier`] is parameterised by.
pub trait ProviderClaims {
    /// What a verified payload is read into.
    type Claims;
    /// Reads a verified token's `payload`.
    fn claims(payload: Value) -> Result<Self::Claims, VerificationError>;
}

/// A failure setting up the verifier during startup.
#[derive(Debug, Error)]
pub enum OidcVerifierError {
    /// The discovery document could not be read.
    #[error(transparent)]
    Discovery(#[from] WellKnownEndpointError),
    /// The discovery document names another issuer than configured.
    #[error("The discovery document is for issuer '{found}', not '{expected}'")]
    IssuerMismatch {
        /// The configured issuer.
        expected: String,
        /// The issuer the document names.
        found: String,
    },
    /// The signing keys could not be loaded.
    #[error("Could not load the signing keys: {0}")]
    SigningKeys(#[from] JwksSourceError),
    /// A provider URL is not HTTPS and plain HTTP was not allowed.
    #[error(transparent)]
    InsecureUrl(#[from] InsecureUrlError),
}

impl OidcVerifierError {
    /// Whether waiting may fix this: the provider is unreachable or answers with a server error
    /// or 429, as while it is still starting. A wrong issuer, a URL that is not HTTPS, a 4xx
    /// answer or a malformed document are configuration mistakes and fail at once.
    fn is_transient(&self) -> bool {
        match self {
            Self::Discovery(WellKnownEndpointError::Unreachable(_)) => true,
            Self::Discovery(WellKnownEndpointError::ErrorStatus(error)) => error
                .status()
                .is_some_and(|status| status.is_server_error() || status.as_u16() == 429),
            Self::SigningKeys(
                JwksSourceError::Unreachable(_) | JwksSourceError::ErrorStatus(_),
            ) => true,
            _ => false,
        }
    }
}

/// Verifies tokens against an OpenID Connect provider: the signature against its published
/// keys, then audience, issuer, expiry and issue time. `P` reads the verified payload.
pub struct OidcVerifier<P> {
    /// The provider's discovery document.
    well_known_endpoint: WellKnownEndpoint,
    /// The provider's signing keys.
    keys: Arc<Cache>,
    /// One per algorithm, built once: the audience and issuer never change after startup.
    validations: HashMap<Algorithm, Validation>,
    /// Which provider's claims reader `P` this verifier uses.
    _marker: PhantomData<fn() -> P>,
}

impl<P> OidcVerifier<P> {
    /// Discovers the provider at `issuer_url` with `client`, accepting tokens for `audience`
    /// over the URLs `transport` allows.
    ///
    /// The issuer is also where this service reaches the provider: browsers and services use
    /// the same address (in a cluster, the public name resolves to the ingress internally too).
    ///
    /// A provider that cannot be reached yet is retried for up to two minutes, with waits from
    /// half a second doubling up to 10 seconds, so a service starting before its provider waits
    /// instead of crashing; configuration mistakes fail at once.
    pub async fn new(
        issuer_url: &str,
        client: reqwest::Client,
        audience: String,
        transport: Transport,
    ) -> Result<Self, OidcVerifierError> {
        retry_transient(
            || Self::discover(issuer_url, client.clone(), &audience, transport),
            OidcVerifierError::is_transient,
            STARTUP_BACKOFF,
        )
        .await
    }

    /// One attempt of [`Self::new`]: reads the discovery document and the signing keys.
    async fn discover(
        issuer_url: &str,
        client: reqwest::Client,
        audience: &str,
        transport: Transport,
    ) -> Result<Self, OidcVerifierError> {
        transport.check("issuer", issuer_url)?;
        let well_known_endpoint = WellKnownEndpoint::fetch(&client, issuer_url).await?;

        // OIDC Discovery 1.0 §4.3: the document must name the issuer it was fetched for,
        // otherwise the endpoint, not this configuration, decides which tokens are accepted.
        if well_known_endpoint.issuer.trim_end_matches('/') != issuer_url.trim_end_matches('/') {
            return Err(OidcVerifierError::IssuerMismatch {
                expected: issuer_url.to_owned(),
                found: well_known_endpoint.issuer,
            });
        }

        well_known_endpoint.check_transport(transport)?;

        let source = HttpJwksSource::new(client, well_known_endpoint.jwks_uri.clone());
        let keys = Cache::new(source, KEY_TTL, KEY_MIN_REFRESH_INTERVAL).await?;
        Ok(Self::from_parts(well_known_endpoint, keys, audience))
    }

    /// A verifier from an already loaded `well_known_endpoint` and `keys`, accepting tokens
    /// for `audience`.
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

    /// The provider's endpoints.
    pub fn well_known_endpoint(&self) -> &WellKnownEndpoint {
        &self.well_known_endpoint
    }

    /// Where codes and refresh tokens are exchanged.
    pub fn token_endpoint(&self) -> &str {
        &self.well_known_endpoint.token_endpoint
    }

    /// Where tokens are revoked, if the provider publishes it.
    pub fn revocation_endpoint(&self) -> Option<&str> {
        self.well_known_endpoint.revocation_endpoint.as_deref()
    }

    /// Where sessions end (RP-Initiated Logout), for the browser and for this service's own
    /// calls alike, e.g. Keycloak's logout with a refresh token. `None` if the provider
    /// publishes none.
    pub fn end_session_endpoint(&self) -> Option<&str> {
        self.well_known_endpoint.end_session_endpoint.as_deref()
    }

    /// Verifies `raw_token` and returns its payload untouched.
    ///
    /// Only an unreachable provider is not the token's fault; every other failure means the
    /// token cannot be trusted, so it is reported as invalid with the specific reason.
    async fn verify_payload(&self, raw_token: &str) -> Result<Value, VerificationError> {
        let header = decode_header(raw_token)
            .map_err(|_| VerificationError::Invalid("malformed token header".to_string()))?;

        // The key id selects which JWK signed this token; without one there is nothing to look up.
        let kid = header
            .kid
            .ok_or_else(|| VerificationError::Invalid("token has no key id".to_string()))?;

        // An unknown key id is the token's fault; a provider that cannot be asked about it is
        // not, so an API can answer 503 instead of 401.
        let key = self.keys.key(&kid).await.map_err(|error| match error {
            JwksSourceError::SigningKeyNotFound(kid) => {
                VerificationError::Invalid(format!("no signing key with id '{kid}'"))
            }
            other => VerificationError::ProviderUnavailable(other.to_string()),
        })?;
        if header.alg != key.algorithm {
            return Err(VerificationError::Invalid(format!(
                "key '{kid}' signs with {:?}, not {:?}",
                key.algorithm, header.alg
            )));
        }
        let validation = self.validations.get(&key.algorithm).ok_or_else(|| {
            VerificationError::Invalid(format!("unsupported algorithm {:?}", header.alg))
        })?;

        let payload = decode::<Value>(raw_token, &key.key, validation)
            .map(|token| token.claims)
            .map_err(|error| VerificationError::Invalid(format!("{:?}", error.into_kind())))?;
        check_issued_at(&payload)?;
        Ok(payload)
    }
}

/// Requires `payload` to have an `iat` that is not in the future: a token "issued" later than
/// now was not made by a provider whose clock agrees with ours.
fn check_issued_at(payload: &Value) -> Result<(), VerificationError> {
    let iat = payload
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or(VerificationError::MissingClaim("iat"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    if iat > now + LEEWAY_SECS {
        return Err(VerificationError::Invalid(
            "token issued in the future".to_string(),
        ));
    }
    Ok(())
}

#[async_trait::async_trait]
impl<P: ProviderClaims> Verifier for OidcVerifier<P>
where
    P::Claims: Send,
{
    type Claims = P::Claims;
    async fn verify(&self, raw_token: &str) -> Result<P::Claims, VerificationError> {
        let payload = self.verify_payload(raw_token).await?;
        P::claims(payload)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    use async_trait::async_trait;
    use aws_lc_rs::{
        rsa::KeySize,
        signature::{KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair},
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::jwk::JwkSet;
    use ring::{
        hmac,
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair},
    };
    use serde_json::{Value, json};

    use super::*;
    use crate::jwks::JwksSource;

    // ---- startup: which setup errors are retried ----

    #[test]
    fn given_setup_errors_then_only_an_unreachable_provider_is_transient() {
        let unreachable = OidcVerifierError::SigningKeys(JwksSourceError::Unreachable("x".into()));
        let failing = OidcVerifierError::SigningKeys(JwksSourceError::ErrorStatus("503".into()));
        let malformed = OidcVerifierError::SigningKeys(JwksSourceError::Malformed("x".into()));
        let mismatch = OidcVerifierError::IssuerMismatch {
            expected: "https://a".into(),
            found: "https://b".into(),
        };
        assert!(unreachable.is_transient());
        assert!(failing.is_transient());
        assert!(!malformed.is_transient());
        assert!(!mismatch.is_transient());
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_plain_http_issuer_without_allowing_it_then_new_fails_before_any_request() {
        let started = tokio::time::Instant::now();
        let result = OidcVerifier::<()>::new(
            "http://keycloak-api/realms/test",
            reqwest::Client::new(),
            "api".into(),
            Transport::HttpsOnly,
        )
        .await;
        assert!(matches!(result, Err(OidcVerifierError::InsecureUrl(_))));
        assert_eq!(started.elapsed(), Duration::ZERO, "not retried");
    }

    // ---- token verification: verify_payload and the Verifier impl ----

    /// The tests' issuer.
    const ISSUER: &str = "https://idp.example/realms/test";
    /// The tests' audience.
    const AUDIENCE: &str = "api";

    /// The current time in Unix seconds.
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// `value` as base64url JSON, as in a JWT.
    fn encode(value: &Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap())
    }

    /// A signing key generated per test, published under its `kid`.
    enum TestKey {
        /// Ed25519, signing EdDSA.
        Ed25519 {
            kid: &'static str,
            pair: Ed25519KeyPair,
        },
        /// ECDSA on P-256, signing ES256.
        Es256 {
            kid: &'static str,
            pair: EcdsaKeyPair,
        },
        /// RSA 2048, signing RS256.
        Rs256 { kid: &'static str, pair: RsaKeyPair },
    }

    impl TestKey {
        /// A fresh Ed25519 key with id `kid`.
        fn ed25519(kid: &'static str) -> Self {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            Self::Ed25519 {
                kid,
                pair: Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap(),
            }
        }

        /// A fresh P-256 key with id `kid`.
        fn es256(kid: &'static str) -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            Self::Es256 {
                kid,
                pair: EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P256_SHA256_FIXED_SIGNING,
                    pkcs8.as_ref(),
                    &rng,
                )
                .unwrap(),
            }
        }

        /// A fresh RSA 2048 key with id `kid`.
        fn rs256(kid: &'static str) -> Self {
            Self::Rs256 {
                kid,
                pair: RsaKeyPair::generate(KeySize::Rsa2048).unwrap(),
            }
        }

        /// The key id.
        fn kid(&self) -> &'static str {
            match self {
                Self::Ed25519 { kid, .. } | Self::Es256 { kid, .. } | Self::Rs256 { kid, .. } => {
                    kid
                }
            }
        }

        /// The algorithm this key signs with.
        fn alg(&self) -> &'static str {
            match self {
                Self::Ed25519 { .. } => "EdDSA",
                Self::Es256 { .. } => "ES256",
                Self::Rs256 { .. } => "RS256",
            }
        }

        /// The public key as a JWK.
        fn jwk(&self) -> Value {
            match self {
                Self::Ed25519 { kid, pair } => json!({
                    "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": kid,
                    "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
                }),
                Self::Es256 { kid, pair } => {
                    // Uncompressed point: 0x04, then x and y, 32 bytes each.
                    let point = pair.public_key().as_ref();
                    json!({
                        "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": kid,
                        "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
                        "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
                    })
                }
                Self::Rs256 { kid, pair } => {
                    let public = pair.public_key();
                    json!({
                        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
                        "n": URL_SAFE_NO_PAD.encode(public.modulus().big_endian_without_leading_zero()),
                        "e": URL_SAFE_NO_PAD.encode(public.exponent().big_endian_without_leading_zero()),
                    })
                }
            }
        }

        /// A JWT of `header` and `claims`, signed with this key whatever the header says.
        fn sign(&self, header: &Value, claims: &Value) -> String {
            let input = format!("{}.{}", encode(header), encode(claims));
            let signature = match self {
                Self::Ed25519 { pair, .. } => pair.sign(input.as_bytes()).as_ref().to_vec(),
                Self::Es256 { pair, .. } => pair
                    .sign(&SystemRandom::new(), input.as_bytes())
                    .unwrap()
                    .as_ref()
                    .to_vec(),
                Self::Rs256 { pair, .. } => {
                    let mut signature = vec![0; pair.public_modulus_len()];
                    pair.sign(
                        &RSA_PKCS1_SHA256,
                        &aws_lc_rs::rand::SystemRandom::new(),
                        input.as_bytes(),
                        &mut signature,
                    )
                    .unwrap();
                    signature
                }
            };
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
        }

        /// A correctly signed JWT carrying `claims`.
        fn token(&self, claims: &Value) -> String {
            self.sign(
                &json!({ "alg": self.alg(), "typ": "JWT", "kid": self.kid() }),
                claims,
            )
        }
    }

    /// A key source serving whatever set it currently holds, counting fetches; `None` means
    /// the endpoint is down.
    #[derive(Debug, Clone)]
    struct TestSource {
        set: Arc<Mutex<Option<JwkSet>>>,
        fetches: Arc<AtomicUsize>,
    }

    impl TestSource {
        /// Serving the public keys of `keys`.
        fn serving(keys: &[&TestKey]) -> Self {
            let source = Self {
                set: Arc::default(),
                fetches: Arc::default(),
            };
            source.serve(keys);
            source
        }

        /// From now on serves the public keys of `keys`.
        fn serve(&self, keys: &[&TestKey]) {
            let jwks: Vec<Value> = keys.iter().map(|key| key.jwk()).collect();
            *self.set.lock().unwrap() =
                Some(serde_json::from_value(json!({ "keys": jwks })).unwrap());
        }

        /// From now on fails, as an unreachable endpoint.
        fn go_down(&self) {
            *self.set.lock().unwrap() = None;
        }

        /// How many times the keys were fetched.
        fn fetches(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl JwksSource for TestSource {
        async fn fetch(&self) -> Result<JwkSet, JwksSourceError> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            self.set
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| JwksSourceError::Unreachable("connection refused".into()))
        }
    }

    /// Hands payloads back untouched.
    struct Raw;

    impl ProviderClaims for Raw {
        type Claims = Value;
        fn claims(payload: Value) -> Result<Value, VerificationError> {
            Ok(payload)
        }
    }

    /// A verifier for [`ISSUER`] and [`AUDIENCE`] fetching its keys from `source`.
    async fn verifier_with<P>(source: TestSource) -> OidcVerifier<P> {
        let keys = Cache::new(source, KEY_TTL, KEY_MIN_REFRESH_INTERVAL)
            .await
            .unwrap();
        let endpoint = |path: &str| format!("{ISSUER}/{path}");
        let well_known = WellKnownEndpoint {
            issuer: ISSUER.to_owned(),
            authorization_endpoint: endpoint("auth"),
            token_endpoint: endpoint("token"),
            end_session_endpoint: Some(endpoint("logout")),
            jwks_uri: endpoint("certs"),
            revocation_endpoint: Some(endpoint("revoke")),
        };
        OidcVerifier::from_parts(well_known, keys, AUDIENCE)
    }

    /// A verifier trusting the `published` keys, handing payloads back untouched.
    async fn verifier(published: &[&TestKey]) -> OidcVerifier<Raw> {
        verifier_with(TestSource::serving(published)).await
    }

    /// Valid claims for a fresh token.
    fn claims() -> Value {
        let now = now();
        json!({ "iss": ISSUER, "aud": AUDIENCE, "sub": "user-1", "iat": now, "exp": now + 300 })
    }

    /// [`claims`] without `claim`.
    fn without(claim: &str) -> Value {
        let mut claims = claims();
        claims.as_object_mut().unwrap().remove(claim);
        claims
    }

    /// [`claims`] with `claim` set to `value`.
    fn with(claim: &str, value: Value) -> Value {
        let mut claims = claims();
        claims[claim] = value;
        claims
    }

    /// Asserts `verifier` refuses `token` as invalid; `why` names the case on failure.
    async fn assert_invalid(verifier: &OidcVerifier<Raw>, token: &str, why: &str) {
        let result = verifier.verify(token).await;
        assert!(
            matches!(result, Err(VerificationError::Invalid(_))),
            "{why}: {result:?}"
        );
    }

    // ---- accepted ----

    #[tokio::test]
    async fn given_a_valid_token_from_an_ed25519_key_then_its_payload_is_returned() {
        let key = TestKey::ed25519("k1");
        let payload = verifier(&[&key])
            .await
            .verify(&key.token(&claims()))
            .await
            .unwrap();
        assert_eq!(payload["sub"], "user-1");
    }

    #[tokio::test]
    async fn given_a_valid_token_from_a_p256_key_then_its_payload_is_returned() {
        let key = TestKey::es256("k1");
        let payload = verifier(&[&key])
            .await
            .verify(&key.token(&claims()))
            .await
            .unwrap();
        assert_eq!(payload["sub"], "user-1");
    }

    #[tokio::test]
    async fn given_a_valid_token_from_an_rsa_key_then_its_payload_is_returned() {
        let key = TestKey::rs256("k1");
        let payload = verifier(&[&key])
            .await
            .verify(&key.token(&claims()))
            .await
            .unwrap();
        assert_eq!(payload["sub"], "user-1");
    }

    #[tokio::test]
    async fn given_an_audience_list_naming_this_service_then_the_token_is_accepted() {
        let key = TestKey::ed25519("k1");
        let token = key.token(&with("aud", json!(["account", AUDIENCE])));
        assert!(verifier(&[&key]).await.verify(&token).await.is_ok());
    }

    // ---- signature ----

    #[tokio::test]
    async fn given_a_tampered_payload_then_the_token_is_refused() {
        let key = TestKey::ed25519("k1");
        let token = key.token(&claims());
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = encode(&with("sub", json!("admin")));
        parts[1] = &forged;
        assert_invalid(
            &verifier(&[&key]).await,
            &parts.join("."),
            "tampered payload",
        )
        .await;
    }

    #[tokio::test]
    async fn given_a_token_signed_by_another_key_with_the_same_kid_then_it_is_refused() {
        let published = TestKey::ed25519("k1");
        let impostor = TestKey::ed25519("k1");
        assert_invalid(
            &verifier(&[&published]).await,
            &impostor.token(&claims()),
            "signed by an unpublished key",
        )
        .await;
    }

    #[tokio::test]
    async fn given_tokens_that_are_not_jwts_then_they_are_refused() {
        let key = TestKey::ed25519("k1");
        let verifier = verifier(&[&key]).await;
        for token in ["", "abc", "a.b", "a.b.c", "not.a.jwt.at.all"] {
            assert_invalid(&verifier, token, token).await;
        }
    }

    // ---- time ----

    #[tokio::test]
    async fn given_an_expired_token_then_it_is_refused_except_within_the_leeway() {
        let key = TestKey::ed25519("k1");
        let verifier = verifier(&[&key]).await;
        let now = now();
        let long_expired = key.token(&with("exp", json!(now - LEEWAY_SECS - 60)));
        assert_invalid(&verifier, &long_expired, "expired past the leeway").await;
        let just_expired = key.token(&with("exp", json!(now - LEEWAY_SECS / 2)));
        assert!(
            verifier.verify(&just_expired).await.is_ok(),
            "within the leeway"
        );
    }

    #[tokio::test]
    async fn given_a_token_not_valid_yet_then_it_is_refused_except_within_the_leeway() {
        let key = TestKey::ed25519("k1");
        let verifier = verifier(&[&key]).await;
        let now = now();
        let later = key.token(&with("nbf", json!(now + LEEWAY_SECS + 60)));
        assert_invalid(&verifier, &later, "nbf past the leeway").await;
        let almost = key.token(&with("nbf", json!(now + LEEWAY_SECS / 2)));
        assert!(verifier.verify(&almost).await.is_ok(), "within the leeway");
    }

    #[tokio::test]
    async fn given_no_iat_then_the_missing_claim_is_named() {
        let key = TestKey::ed25519("k1");
        let result = verifier(&[&key])
            .await
            .verify(&key.token(&without("iat")))
            .await;
        assert!(
            matches!(result, Err(VerificationError::MissingClaim("iat"))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn given_an_iat_in_the_future_then_it_is_refused_except_within_the_leeway() {
        let key = TestKey::ed25519("k1");
        let verifier = verifier(&[&key]).await;
        let now = now();
        let future = key.token(&with("iat", json!(now + LEEWAY_SECS + 60)));
        assert_invalid(&verifier, &future, "issued in the future").await;
        let skewed = key.token(&with("iat", json!(now + LEEWAY_SECS / 2)));
        assert!(
            verifier.verify(&skewed).await.is_ok(),
            "clock skew within the leeway"
        );
    }

    // ---- claims ----

    #[tokio::test]
    async fn given_a_token_without_exp_iss_or_aud_then_it_is_refused() {
        let key = TestKey::ed25519("k1");
        let verifier = verifier(&[&key]).await;
        for claim in ["exp", "iss", "aud"] {
            assert_invalid(&verifier, &key.token(&without(claim)), claim).await;
        }
    }

    #[tokio::test]
    async fn given_another_issuer_or_audience_then_the_token_is_refused() {
        let key = TestKey::ed25519("k1");
        let verifier = verifier(&[&key]).await;
        let other_issuer = key.token(&with("iss", json!("https://idp.example/realms/other")));
        assert_invalid(&verifier, &other_issuer, "another issuer").await;
        let other_audience = key.token(&with("aud", json!("billing-api")));
        assert_invalid(&verifier, &other_audience, "another audience").await;
        let audience_list = key.token(&with("aud", json!(["account", "billing-api"])));
        assert_invalid(&verifier, &audience_list, "a list without this audience").await;
    }

    // ---- algorithms and key ids ----

    #[tokio::test]
    async fn given_a_token_without_a_key_id_then_it_is_refused() {
        let key = TestKey::ed25519("k1");
        let token = key.sign(&json!({ "alg": "EdDSA", "typ": "JWT" }), &claims());
        assert_invalid(&verifier(&[&key]).await, &token, "no kid").await;
    }

    #[tokio::test]
    async fn given_an_unsigned_token_then_it_is_refused() {
        let key = TestKey::ed25519("k1");
        let header = encode(&json!({ "alg": "none", "kid": "k1" }));
        let token = format!("{header}.{}.", encode(&claims()));
        assert_invalid(&verifier(&[&key]).await, &token, "alg none").await;
    }

    #[tokio::test]
    async fn given_a_header_algorithm_other_than_the_keys_then_the_token_is_refused() {
        let key = TestKey::ed25519("k1");
        // Signed correctly, but the header claims another algorithm: the key decides, not the header.
        let token = key.sign(
            &json!({ "alg": "ES256", "typ": "JWT", "kid": "k1" }),
            &claims(),
        );
        assert_invalid(
            &verifier(&[&key]).await,
            &token,
            "header alg differs from the key's",
        )
        .await;
    }

    #[tokio::test]
    async fn given_an_hmac_token_keyed_with_the_public_key_then_it_is_refused() {
        let key = TestKey::ed25519("k1");
        // The classic confusion attack: sign HS256 with the public key as the shared secret.
        let public = URL_SAFE_NO_PAD
            .decode(key.jwk()["x"].as_str().unwrap())
            .unwrap();
        let input = format!(
            "{}.{}",
            encode(&json!({ "alg": "HS256", "typ": "JWT", "kid": "k1" })),
            encode(&claims())
        );
        let tag = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, &public),
            input.as_bytes(),
        );
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(tag.as_ref()));
        assert_invalid(
            &verifier(&[&key]).await,
            &token,
            "HS256 with the public key",
        )
        .await;
    }

    // ---- key rotation and an unreachable provider ----

    #[tokio::test(start_paused = true)]
    async fn given_a_key_rotated_in_at_the_provider_then_its_tokens_verify_after_one_refetch() {
        let old = TestKey::ed25519("old");
        let new = TestKey::ed25519("new");
        let source = TestSource::serving(&[&old]);
        let verifier = verifier_with::<Raw>(source.clone()).await;
        assert_eq!(source.fetches(), 1, "loaded at startup");

        source.serve(&[&old, &new]);
        // Past the cooldown between fetches, an unknown key id triggers one refetch.
        tokio::time::advance(KEY_MIN_REFRESH_INTERVAL + Duration::from_secs(1)).await;
        assert!(verifier.verify(&new.token(&claims())).await.is_ok());
        assert_eq!(source.fetches(), 2);
        assert!(verifier.verify(&new.token(&claims())).await.is_ok());
        assert_eq!(source.fetches(), 2, "the new key is cached");
    }

    #[tokio::test(start_paused = true)]
    async fn given_an_unknown_key_id_then_the_token_is_refused_after_at_most_one_refetch() {
        let key = TestKey::ed25519("k1");
        let stranger = TestKey::ed25519("unknown");
        let source = TestSource::serving(&[&key]);
        let verifier = verifier_with::<Raw>(source.clone()).await;
        tokio::time::advance(KEY_MIN_REFRESH_INTERVAL + Duration::from_secs(1)).await;
        for _ in 0..5 {
            assert_invalid(&verifier, &stranger.token(&claims()), "unknown key id").await;
        }
        assert_eq!(
            source.fetches(),
            2,
            "a burst of unknown key ids fetches once"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn given_the_key_endpoint_down_then_known_keys_still_verify_and_unknown_ones_report_it() {
        let key = TestKey::ed25519("k1");
        let rotated = TestKey::ed25519("k2");
        let source = TestSource::serving(&[&key]);
        let verifier = verifier_with::<Raw>(source.clone()).await;
        source.go_down();
        tokio::time::advance(KEY_MIN_REFRESH_INTERVAL + Duration::from_secs(1)).await;

        assert!(
            verifier.verify(&key.token(&claims())).await.is_ok(),
            "a known key keeps working while the provider is down"
        );
        let result = verifier.verify(&rotated.token(&claims())).await;
        // An unreachable provider is not the token's fault: the API answers 503, not 401.
        assert!(
            matches!(result, Err(VerificationError::ProviderUnavailable(_))),
            "{result:?}"
        );
    }

    // ---- the provider's claims reader ----

    /// Reads only the subject.
    struct Subject;

    impl ProviderClaims for Subject {
        type Claims = String;
        fn claims(payload: Value) -> Result<String, VerificationError> {
            payload["sub"]
                .as_str()
                .map(str::to_owned)
                .ok_or(VerificationError::MissingClaim("sub"))
        }
    }

    /// Requires a `tenant` claim the test tokens do not have.
    struct NeedsTenant;

    impl ProviderClaims for NeedsTenant {
        type Claims = ();
        fn claims(payload: Value) -> Result<(), VerificationError> {
            payload
                .get("tenant")
                .map(|_| ())
                .ok_or(VerificationError::MissingClaim("tenant"))
        }
    }

    #[tokio::test]
    async fn given_a_claims_reader_then_verify_returns_what_it_reads_or_its_error() {
        let key = TestKey::ed25519("k1");
        let token = key.token(&claims());

        let subject = verifier_with::<Subject>(TestSource::serving(&[&key])).await;
        assert_eq!(subject.verify(&token).await.unwrap(), "user-1");

        let tenant = verifier_with::<NeedsTenant>(TestSource::serving(&[&key])).await;
        assert!(matches!(
            tenant.verify(&token).await,
            Err(VerificationError::MissingClaim("tenant"))
        ));
    }

    #[tokio::test]
    async fn given_an_invalid_token_then_the_claims_reader_is_never_called() {
        let key = TestKey::ed25519("k1");
        let expired = key.token(&with("exp", json!(now() - 3600)));
        // NeedsTenant would answer MissingClaim; an invalid token must stop before it.
        let tenant = verifier_with::<NeedsTenant>(TestSource::serving(&[&key])).await;
        assert!(matches!(
            tenant.verify(&expired).await,
            Err(VerificationError::Invalid(_))
        ));
    }
}
