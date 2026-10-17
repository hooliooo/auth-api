use std::env;

use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to create listener");
    let oauth2_url = env_string(
        "OAUTH2_BASE_URL",
        "http://keycloak-auth-layer:8080/realms/test".to_string(),
    );

    let database_url = env_string(
        "DATABASE_URL",
        "postgres://auth_layer_admin:test@localhost:5433/auth_layer".to_string(),
    );

    let audience = env_string("AUDIENCE", "authentication.layer.api".to_string());

    // Plain HTTP to the identity provider only when explicitly allowed, for a local dev stack.
    let transport = match env::var("ALLOW_INSECURE_HTTP").as_deref() {
        Err(_) | Ok("false") => rest_api::Transport::HttpsOnly,
        Ok("true") => rest_api::Transport::AllowInsecureHttp,
        Ok(other) => panic!("ALLOW_INSECURE_HTTP must be true or false, not '{other}'"),
    };

    // Whose access tokens are accepted: `oidc` (any OpenID Connect provider) or `keycloak`.
    // Required: a Keycloak deployment must never fall back to the standard checks unnoticed.
    let setting = env::var("IDENTITY_PROVIDER").expect("IDENTITY_PROVIDER must be set");
    let provider = rest_api::IdentityProvider::from_setting(&setting)
        .unwrap_or_else(|| panic!("IDENTITY_PROVIDER must be oidc or keycloak, not '{setting}'"));

    rest_api::run(
        listener,
        &oauth2_url,
        &database_url,
        &audience,
        transport,
        provider,
    )
    .await
    .expect("Failed to bind address")
}

fn env_string(key: &str, default: String) -> String {
    match env::var(key) {
        Ok(raw) => raw,
        Err(_) => default,
    }
}
