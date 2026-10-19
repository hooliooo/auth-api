use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use jsonwebtoken::{
    Algorithm, DecodingKey,
    jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, PublicKeyUse},
};
use thiserror::Error;
use tokio::time::Instant;

pub mod cache;
#[cfg(test)]
mod fixtures;

#[derive(Debug, Error)]
pub enum JwksSourceError {
    /// The connection failed.
    #[error("Could not reach the JWKS endpoint: {0}")]
    Unreachable(String),
    /// The endpoint answered with an error status.
    #[error("The JWKS endpoint returned an error: {0}")]
    ErrorStatus(String),
    /// The body is not a key set.
    #[error("The JWKS endpoint did not return a key set: {0}")]
    Malformed(String),
    /// Signing key not found.
    #[error("The signing key with kid: '{0}' was not found")]
    SigningKeyNotFound(String),
}

/// Where the JSON Web Key Set (JWKS) comes from. A trait so the cache can be tested without
/// HTTP.
#[async_trait]
pub trait JwksSource: std::fmt::Debug + Send + Sync {
    /// The current key set.
    async fn fetch(&self) -> Result<JwkSet, JwksSourceError>;
}

/// Fetches the JWKS from the provider's `jwks_uri`.
#[derive(Debug)]
pub struct HttpJwksSource {
    /// Client the key set is fetched with.
    client: reqwest::Client,
    /// The provider's `jwks_uri`.
    jwks_uri: String,
}

#[async_trait]
impl JwksSource for HttpJwksSource {
    async fn fetch(&self) -> Result<JwkSet, JwksSourceError> {
        self.client
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|err| JwksSourceError::Unreachable(err.to_string()))?
            .error_for_status()
            .map_err(|err| JwksSourceError::ErrorStatus(err.to_string()))?
            .json()
            .await
            .map_err(|err| JwksSourceError::Malformed(err.to_string()))
    }
}

/// A key that verifies signatures
#[derive(Debug)]
pub struct SigningKey {
    /// The public key
    pub key: DecodingKey,
    /// The algorithm used by this key to sign tokens
    pub algorithm: Algorithm,
}

/// One fetched key set, keyed by key id. Replaced as a whole on every refresh.
#[derive(Debug)]
struct Keys {
    /// Signing keys by kid
    by_kid: HashMap<String, Arc<SigningKey>>,
    /// The timestamp of when the keys were fetched
    fetched_at: Instant,
}

impl Keys {
    /// The usable signing keys of `set`, fetched at `fetched_at`. Other keys are skipped rather
    /// than failing the whole set: a JWKS may also list encryption keys or other algorithms.
    fn from_set(set: &JwkSet, fetched_at: Instant) -> Self {
        let by_kid = set
            .keys
            .iter()
            .filter(|jwk| !matches!(jwk.common.public_key_use, Some(PublicKeyUse::Encryption)))
            .filter_map(|jwk| {
                let kid = jwk.common.key_id.clone()?;
                let algorithm = signing_algoritm(jwk)?;
                let key = DecodingKey::from_jwk(jwk).ok()?;
                Some((kid, Arc::new(SigningKey { key, algorithm })))
            })
            .collect::<HashMap<String, Arc<SigningKey>>>();

        Self { by_kid, fetched_at }
    }
}

/// The algorithm `jwk` signs with: its `alg` if set, otherwise its key type's usual one.
/// `None` for keys that cannot be used, including symmetric ones: a secret in a public key set
/// would let anyone who reads it sign tokens.
fn signing_algoritm(jwk: &Jwk) -> Option<Algorithm> {
    let algorithm = match (jwk.common.key_algorithm, &jwk.algorithm) {
        (_, AlgorithmParameters::OctetKey(_)) => return None,
        (Some(key_algorithm), _) => Algorithm::try_from(key_algorithm).ok()?,
        (None, AlgorithmParameters::RSA(_)) => Algorithm::RS256,
        (None, AlgorithmParameters::EllipticCurve(params)) => match params.curve {
            EllipticCurve::P256 => Algorithm::ES256,
            EllipticCurve::P384 => Algorithm::ES384,
            _ => return None,
        },
        (None, AlgorithmParameters::OctetKeyPair(_)) => Algorithm::EdDSA,
        (None, _) => return None,
    };
    let symmetric = matches!(
        algorithm,
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
    );
    (!symmetric).then_some(algorithm)
}

#[cfg(test)]
mod tests {

    use jsonwebtoken::Algorithm;
    use serde_json::json;

    use crate::jwks::{
        Keys,
        fixtures::{MODULUS, rsa_key, set_of},
    };

    #[tokio::test(start_paused = true)]
    async fn given_a_key_set_when_loaded_then_only_signing_keys_should_be_kept() {
        let kid = "ulvOORCVelRFp5JKoU9H21TJZBSqk2YY7N59oZpcgfs";
        let set = set_of(vec![
            rsa_key(kid),
            json!({ "kty": "RSA", "use": "enc", "kid": "encryption", "n": MODULUS, "e": "AQAB" }),
            json!({ "kty": "oct", "kid": "secret", "k": "c2VjcmV0" }),
            json!({ "kty": "RSA", "use": "sig", "n": MODULUS, "e": "AQAB" }),
        ]);

        let keys = Keys::from_set(&set, tokio::time::Instant::now());
        assert_eq!(keys.by_kid.len(), 1);
        assert!(keys.by_kid.contains_key(kid));
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_key_without_alg_when_loaded_it_should_use_its_key_types_default() {
        let set = set_of(vec![
            json!({"kty": "RSA", "kid": "no-alg", "n": MODULUS, "e": "AQAB"}),
        ]);

        let keys = Keys::from_set(&set, tokio::time::Instant::now());
        assert_eq!(keys.by_kid["no-alg"].algorithm, Algorithm::RS256);
    }
}
