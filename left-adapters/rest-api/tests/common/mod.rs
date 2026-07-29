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

            tokio::spawn(async move {
                rest_api::run(listener).await.unwrap();
            });

            addr
        })
        .await
}

pub fn setup_env_vars() {
    dotenvy::from_filename("tests/.env").ok();
}

pub struct TestEnv {
    pub address: SocketAddr,
    pub access_token: String,
}

pub async fn load_env_and_extract_access_token() -> TestEnv {
    setup_env_vars();
    let base_url = std::env::var("OAUTH2_BASE_URL").expect("OAUTH2_BASE_URL should be set");
    let token_url = format!("{}/protocol/openid-connect/token", base_url);
    let client_id = std::env::var("OAUTH2_CLIENT_ID").expect("No client id");
    let client_secret = std::env::var("OAUTH2_CLIENT_SECRET").expect("No client secret");
    let address = get_server_address().await;

    let params = {
        let mut params = HashMap::new();
        params.insert("grant_type", "client_credentials");
        params.insert("client_id", &client_id);
        params.insert("client_secret", &client_secret);
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
