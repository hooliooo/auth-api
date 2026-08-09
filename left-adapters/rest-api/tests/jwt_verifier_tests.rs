use crate::common::TEST_HTTP_CLIENT;
use reqwest::Client;
use rest_api::authorization::jwt::JwtVerifier;
use rest_api::authorization::jwt::KeycloakJwtVerifier;
use std::collections::HashMap;

pub mod common;

#[cfg(feature = "e2e")]
#[tokio::test]
async fn test_jwt_verifier() {
    use auth_core::domain::authorization::authorized_scope::AuthorizedScope;

    let issuer_url = "http://keycloak-auth-layer:8080/realms/test";
    let client = Client::new();
    let verifier = KeycloakJwtVerifier::new(
        issuer_url,
        client,
        "authentication.layer.api".to_string(),
        false,
    )
    .await
    .unwrap();

    let params = {
        let mut params = HashMap::new();
        params.insert("grant_type", "client_credentials");
        params.insert("client_id", "end.to.end.client");
        params.insert("client_secret", "end.to.end.client.secret");
        params
    };

    let response = TEST_HTTP_CLIENT
        .post(verifier.token_endpoint())
        .form(&params)
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .expect("Request failed");

    dbg!(format_args!("Response: {:?}", response.clone()));

    let access_token = response
        .get("access_token")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();

    let token = verifier.verify(&access_token).await.unwrap();
    let claims = token.extract().unwrap();
    assert_eq!(claims.authorized_scope, AuthorizedScope::SuperAdmin);
}
