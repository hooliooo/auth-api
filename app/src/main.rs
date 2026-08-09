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

    rest_api::run(listener, &oauth2_url, &database_url, &audience)
        .await
        .expect("Failed to bind address")
}

fn env_string(key: &str, default: String) -> String {
    match env::var(key) {
        Ok(raw) => raw,
        Err(_) => default,
    }
}
