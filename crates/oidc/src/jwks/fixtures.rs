//! Test fixtures shared by the `jwks` tests.

use jsonwebtoken::jwk::JwkSet;
use serde_json::{Value, json};

/// Placeholder key material: valid base64url, but no real key. `DecodingKey::from_jwk`
/// only decodes it, and no signature is checked here.
pub(crate) const MODULUS: &str =
    "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QA";

/// A placeholder RSA signing key with id `kid`.
pub(crate) fn rsa_key(kid: &str) -> Value {
    json!({ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": MODULUS, "e": "AQAB" })
}

/// A key set of `keys`.
pub(crate) fn set_of(keys: Vec<Value>) -> JwkSet {
    serde_json::from_value(json!({ "keys": keys })).unwrap()
}

/// A key set with one placeholder key per id in `kids`.
pub(crate) fn key_set(kids: &[&str]) -> JwkSet {
    set_of(kids.iter().map(|kid| rsa_key(kid)).collect())
}
