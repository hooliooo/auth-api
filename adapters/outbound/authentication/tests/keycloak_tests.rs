//! Verifies a real token against the Keycloak from `docker/`. Requires that stack to be running.

#[cfg(feature = "e2e")]
#[tokio::test]
async fn test_jwt_verifier() {
    use std::collections::HashMap;

    use auth_core::application::authentication::JwtVerifier;
    use auth_core::application::authorization::authorized_scope::AuthorizedScope;
    use authentication::KeycloakJwtVerifier;
    use reqwest::Client;

    let issuer_url = "http://keycloak-auth-layer:8080/realms/test";
    let client = Client::new();
    let verifier = KeycloakJwtVerifier::new(
        issuer_url,
        client.clone(),
        "authentication.layer.api".to_string(),
    )
    .await
    .unwrap();

    let params = HashMap::from([
        ("grant_type", "client_credentials"),
        ("client_id", "end.to.end.client"),
        ("client_secret", "end.to.end.client.secret"),
    ]);

    let response = client
        .post(verifier.token_endpoint())
        .form(&params)
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .expect("Request failed");

    let access_token = response
        .get("access_token")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();

    let claims = verifier.verify(&access_token).await.unwrap();
    assert_eq!(claims.authorized_scope, AuthorizedScope::SuperAdmin);
}
