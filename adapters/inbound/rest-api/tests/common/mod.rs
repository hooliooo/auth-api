#![allow(dead_code)]
use std::{collections::HashMap, net::SocketAddr, sync::LazyLock};

use tokio::{net::TcpListener, sync::OnceCell};

pub static TEST_HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);
pub static SERVER_ADDRESS: OnceCell<SocketAddr> = OnceCell::const_new();

pub async fn get_server_address() -> SocketAddr {
    *SERVER_ADDRESS
        .get_or_init(|| async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("Cannot bind");
            let addr = listener.local_addr().unwrap();

            let oauth2_url = "http://keycloak-auth-layer:8080/realms/test".to_string();
            let database_url =
                "postgres://auth_layer_admin:test@localhost:5433/auth_layer".to_string();
            let audience = "authentication.layer.api".to_string();

            tokio::spawn(async move {
                rest_api::run(listener, &oauth2_url, &database_url, &audience)
                    .await
                    .unwrap();
            });

            addr
        })
        .await
}

pub struct TestEnv {
    pub address: SocketAddr,
    pub access_token: String,
}

pub async fn load_env_and_extract_access_token() -> TestEnv {
    let oauth2_url = "http://keycloak-auth-layer:8080/realms/test".to_string();
    let token_url = format!("{}/protocol/openid-connect/token", oauth2_url);
    let client_id = "end.to.end.client";
    let client_secret = "end.to.end.client.secret";
    let address = get_server_address().await;

    let params = {
        let mut params = HashMap::new();
        params.insert("grant_type", "client_credentials");
        params.insert("client_id", client_id);
        params.insert("client_secret", client_secret);
        params
    };

    let token = TEST_HTTP_CLIENT
        .post(token_url)
        .form(&params)
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();

    let access_token = token
        .get("access_token")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();

    TestEnv {
        address,
        access_token,
    }
}
