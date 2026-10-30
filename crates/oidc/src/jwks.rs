//! The provider's signing keys: fetching its JSON Web Key Set (JWKS) and keeping the keys that
//! can verify signatures.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use jsonwebtoken::{
    Algorithm, DecodingKey,
    jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, PublicKeyUse},
};
use thiserror::Error;
use tokio::time::Instant;

use crate::causes::with_causes;

pub mod cache;
#[cfg(test)]
mod fixtures;

/// Why the signing keys could not be loaded, or a token's key could not be found.
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

impl HttpJwksSource {
    /// Fetches from `jwks_uri` with `client`.
    pub fn new(client: reqwest::Client, jwks_uri: String) -> Self {
        Self { client, jwks_uri }
    }
}

#[async_trait]
impl JwksSource for HttpJwksSource {
    async fn fetch(&self) -> Result<JwkSet, JwksSourceError> {
        self.client
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|err| JwksSourceError::Unreachable(with_causes(&err)))?
            .error_for_status()
            .map_err(|err| JwksSourceError::ErrorStatus(with_causes(&err)))?
            .json()
            .await
            .map_err(|err| JwksSourceError::Malformed(with_causes(&err)))
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
    use serde_json::{Value, json};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use crate::jwks::{
        HttpJwksSource, JwksSource, JwksSourceError, Keys,
        fixtures::{MODULUS, rsa_key, set_of},
    };

    /// Placeholder EC/OKP coordinate: valid base64url, but no real point. Like [`MODULUS`],
    /// it is only decoded, never used to verify a signature.
    const COORDINATE: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";

    /// A placeholder EC signing key with id `kid` on curve `crv`, without an `alg`.
    fn ec_key(kid: &str, crv: &str) -> Value {
        json!({ "kty": "EC", "use": "sig", "kid": kid, "crv": crv, "x": COORDINATE, "y": COORDINATE })
    }

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

    #[tokio::test(start_paused = true)]
    async fn given_an_asymmetric_key_with_a_symmetric_alg_when_loaded_then_it_should_be_skipped() {
        // An RSA key claiming HS256: accepting it would invite algorithm confusion, where the
        // public key is used as an HMAC secret.
        let set = set_of(vec![json!({
            "kty": "RSA", "use": "sig", "alg": "HS256", "kid": "confused", "n": MODULUS, "e": "AQAB"
        })]);

        let keys = Keys::from_set(&set, tokio::time::Instant::now());
        assert!(keys.by_kid.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn given_an_ec_key_without_alg_when_loaded_it_should_use_its_curves_default() {
        let set = set_of(vec![ec_key("p256", "P-256"), ec_key("p384", "P-384")]);

        let keys = Keys::from_set(&set, tokio::time::Instant::now());
        assert_eq!(keys.by_kid["p256"].algorithm, Algorithm::ES256);
        assert_eq!(keys.by_kid["p384"].algorithm, Algorithm::ES384);
    }

    #[tokio::test(start_paused = true)]
    async fn given_an_ec_key_on_an_unsupported_curve_when_loaded_then_it_should_be_skipped() {
        let set = set_of(vec![ec_key("p521", "P-521")]);

        let keys = Keys::from_set(&set, tokio::time::Instant::now());
        assert!(keys.by_kid.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn given_an_okp_key_without_alg_when_loaded_it_should_use_eddsa() {
        let set = set_of(vec![json!({
            "kty": "OKP", "use": "sig", "kid": "ed", "crv": "Ed25519", "x": COORDINATE
        })]);

        let keys = Keys::from_set(&set, tokio::time::Instant::now());
        assert_eq!(keys.by_kid["ed"].algorithm, Algorithm::EdDSA);
    }

    #[tokio::test(start_paused = true)]
    async fn given_an_undecodable_key_when_loaded_then_only_that_key_should_be_skipped() {
        let set = set_of(vec![
            rsa_key("good"),
            json!({ "kty": "RSA", "use": "sig", "kid": "broken", "n": "not base64!", "e": "AQAB" }),
        ]);

        let keys = Keys::from_set(&set, tokio::time::Instant::now());
        assert_eq!(keys.by_kid.len(), 1);
        assert!(keys.by_kid.contains_key("good"));
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_key_with_a_key_management_alg_when_loaded_then_it_should_be_skipped() {
        // RSA-OAEP wraps content keys; it is no signing algorithm. No `use`, so only the
        // algorithm check can reject it.
        let set = set_of(vec![json!({
            "kty": "RSA", "alg": "RSA-OAEP", "kid": "wrapping", "n": MODULUS, "e": "AQAB"
        })]);

        let keys = Keys::from_set(&set, tokio::time::Instant::now());
        assert!(keys.by_kid.is_empty());
    }

    /// A local server answering every request with `status` and `body`; returns its base URL.
    async fn answering(status: u16, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        base
    }

    /// Fetches the key set at `url`.
    async fn fetch(url: String) -> Result<jsonwebtoken::jwk::JwkSet, JwksSourceError> {
        HttpJwksSource::new(reqwest::Client::new(), url)
            .fetch()
            .await
    }

    #[tokio::test]
    async fn given_a_failing_key_endpoint_then_the_source_says_how_it_failed() {
        assert!(matches!(
            fetch(answering(500, "").await).await,
            Err(JwksSourceError::ErrorStatus(_))
        ));
        assert!(matches!(
            fetch(answering(200, "not a key set").await).await,
            Err(JwksSourceError::Malformed(_))
        ));
        // A port nothing listens on.
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = closed.local_addr().unwrap();
        drop(closed);
        assert!(matches!(
            fetch(format!("http://{address}/certs")).await,
            Err(JwksSourceError::Unreachable(_))
        ));
    }
}
