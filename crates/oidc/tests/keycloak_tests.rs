//! Against the local cluster's Keycloak (`dev/k8s/up.sh`), at its public address over HTTPS,
//! the way services in the cluster reach it. Only with `--features e2e`, and with the end-to-end
//! client's secret, which the cluster generated:
//!
//! OIDC_E2E_CLIENT_SECRET=$(kubectl -n auth-api get secret keycloak-clients \
//!   -o jsonpath='{.data.end-to-end-client-secret}' | base64 -d) cargo test -p oidc --features e2e
#![cfg(feature = "e2e")]

use oidc::{OidcVerifier, ProviderClaims, VerificationError, Verifier, well_known::Transport};
use serde_json::Value;

/// The test realm's issuer: the same for browsers and services.
const ISSUER: &str = "https://keycloak-api/realms/test";

#[tokio::test]
async fn given_keycloak_at_its_public_address_then_discovery_and_keys_load_over_https() {
    // HTTPS only, as in production; this machine trusts the local CA (`mkcert -install`).
    let verifier = OidcVerifier::<()>::new(
        ISSUER,
        reqwest::Client::new(),
        "account".into(),
        Transport::HttpsOnly,
    )
    .await
    .expect("Keycloak is reachable at its public address and its keys load");

    let endpoints = verifier.well_known_endpoint();
    assert_eq!(endpoints.issuer, ISSUER);
    for url in [
        endpoints.authorization_endpoint.as_str(),
        endpoints.token_endpoint.as_str(),
        endpoints.jwks_uri.as_str(),
    ] {
        assert!(
            url.starts_with(ISSUER),
            "every endpoint under the one address: {url}"
        );
    }
    assert!(
        verifier
            .end_session_endpoint()
            .is_some_and(|url| url.starts_with(ISSUER)),
        "the browser and this service end sessions at the same address"
    );
}

/// The audience the end-to-end client's access tokens carry (the realm setup's audience mapper).
const API_AUDIENCE: &str = "authentication.layer.api";

/// Hands payloads back untouched.
struct Raw;

impl ProviderClaims for Raw {
    type Claims = Value;
    fn claims(payload: Value) -> Result<Value, VerificationError> {
        Ok(payload)
    }
}

/// An access token for the end-to-end client (client credentials), from Keycloak.
async fn access_token() -> String {
    let secret = std::env::var("OIDC_E2E_CLIENT_SECRET").expect(
        "set OIDC_E2E_CLIENT_SECRET to the cluster's end-to-end client secret (see the header)",
    );
    let response: Value = reqwest::Client::new()
        .post(format!("{ISSUER}/protocol/openid-connect/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "end.to.end.client"),
            ("client_secret", secret.as_str()),
        ])
        .send()
        .await
        .expect("Keycloak answers")
        .error_for_status()
        .expect("Keycloak issues the token")
        .json()
        .await
        .unwrap();
    response["access_token"].as_str().unwrap().to_owned()
}

/// A verifier for `audience`, reading payloads untouched.
async fn verifier_for(audience: &str) -> OidcVerifier<Raw> {
    OidcVerifier::new(
        ISSUER,
        reqwest::Client::new(),
        audience.into(),
        Transport::HttpsOnly,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn given_a_real_keycloak_access_token_then_it_verifies_for_its_audience() {
    let payload = verifier_for(API_AUDIENCE)
        .await
        .verify(&access_token().await)
        .await
        .expect("Keycloak's own token verifies");
    assert_eq!(payload["iss"], ISSUER);
    assert_eq!(payload["azp"], "end.to.end.client");
}

#[tokio::test]
async fn given_a_real_keycloak_token_for_another_audience_then_it_is_refused() {
    let result = verifier_for("billing-api")
        .await
        .verify(&access_token().await)
        .await;
    assert!(
        matches!(result, Err(VerificationError::Invalid(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn given_a_real_keycloak_token_with_a_changed_payload_then_it_is_refused() {
    let token = access_token().await;
    let mut parts: Vec<&str> = token.split('.').collect();
    // Keep the signature, swap the payload for one with another subject.
    let forged = {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let mut payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        payload["sub"] = "someone-else".into();
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
    };
    parts[1] = &forged;
    let result = verifier_for(API_AUDIENCE)
        .await
        .verify(&parts.join("."))
        .await;
    assert!(
        matches!(result, Err(VerificationError::Invalid(_))),
        "{result:?}"
    );
}
