use std::{collections::HashMap, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::aio::MultiplexedConnection;
use regex::Regex;
use reqwest::{
    Client, RequestBuilder, Response, StatusCode, Url,
    header::{COOKIE, LOCATION, SET_COOKIE},
    redirect::Policy,
};
use ring::{
    aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    digest::{SHA256, digest},
    hkdf::Salt,
};

pub const USERNAME: &str = "alice";
pub const PASSWORD: &str = "test";

static SIGN_IN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub fn bff_base() -> Url {
    let base_url = std::env::var("E2E_BFF_URL").unwrap_or_else(|_| "http://localhost:5100".into());
    Url::parse(&base_url).expect("E2E_BFF_URL should be a Url")
}

pub fn bff(path: &str) -> Url {
    bff_base().join(path).expect("Paths should join the Url")
}

/// One cookie jar for everything. Emulates a real browser
pub struct Browser {
    http: Client,
    jar: HashMap<String, String>,
}

impl Browser {
    pub fn new() -> Self {
        let http = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Client should build");
        Self {
            http,
            jar: HashMap::default(),
        }
    }

    pub async fn get(&mut self, url: &str) -> Response {
        let request = self.http.get(url);
        self.send(request).await
    }

    /// A `fetch()`-style POST with no body and the given extra headers.
    pub async fn post(&mut self, url: &str, headers: &[(&str, &str)]) -> Response {
        let mut request = self.http.post(url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        self.send(request).await
    }

    pub async fn post_form(&mut self, url: &str, form: &[(&str, &str)]) -> Response {
        let request = self.http.post(url).form(form);
        self.send(request).await
    }

    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.jar.get(name).map(String::as_str)
    }

    async fn send(&mut self, request: RequestBuilder) -> Response {
        let request = if self.jar.is_empty() {
            request
        } else {
            let header = self
                .jar
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(";");
            request.header(COOKIE, header)
        };
        let response = request
            .send()
            .await
            .expect("The request should reach the server");

        for raw in set_cookies(&response) {
            let Some((pair, attributes)) = raw.split_once(';').or(Some((raw.as_str(), ""))) else {
                continue;
            };
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if attributes.to_ascii_lowercase().contains("max-age=0") {
                self.jar.remove(name);
            } else {
                self.jar.insert(name.to_owned(), value.to_owned());
            }
        }
        response
    }
}

pub fn set_cookies(response: &Response) -> Vec<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect()
}

pub fn set_cookie(response: &Response, name: &str) -> Option<String> {
    set_cookies(response)
        .into_iter()
        .find(|c| c.starts_with(&format!("{name}=")))
}

/// The redirect target, resolved against the BFF for relative locations.
pub fn location(response: &Response) -> Url {
    let raw = response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_else(|| {
            panic!(
                "Status: '{}' The response should have a Location",
                response.status()
            )
        });
    bff_base().join(raw).expect("Location is a URL")
}

pub fn query_param(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

pub fn login_url(return_url: &str) -> String {
    let mut url = bff("/auth/login");
    url.query_pairs_mut().append_pair("returnUrl", return_url);
    url.to_string()
}

pub async fn sign_in_until_callback(browser: &mut Browser, return_url: &str) -> Url {
    let _one_at_a_time = SIGN_IN.lock().await;
    let login = browser.get(&login_url(return_url)).await;
    assert_eq!(
        login.status(),
        StatusCode::SEE_OTHER,
        "login should redirect"
    );

    let page = browser.get(location(&login).as_str()).await;

    if page.status() == StatusCode::FOUND {
        return location(&page);
    }

    assert_eq!(
        page.status(),
        StatusCode::OK,
        "Keycloak login page should appear"
    );

    let action = login_form_action(&page.text().await.expect("login forms should be found"));

    let submitted = browser
        .post_form(
            &action,
            &[
                ("username", USERNAME),
                ("password", PASSWORD),
                ("credentialId", ""),
            ],
        )
        .await;

    assert_eq!(
        submitted.status(),
        StatusCode::FOUND,
        "Keycloak should accept the credentials"
    );

    // assert!(
    //     matches!(submitted.status(), StatusCode::FOUND | StatusCode::OK),
    //     "Keycloak should accept the credentials"
    // );

    location(&submitted)
}

/// A complete sign-in; returns the BFF's callback response.
pub async fn sign_in(browser: &mut Browser, return_url: &str) -> Response {
    let callback = sign_in_until_callback(browser, return_url).await;
    browser.get(callback.as_str()).await
}

fn login_form_action(html: &str) -> String {
    let form = Regex::new(r#"(?s)<form\b[^>]*\bid="kc-form-login"[^>]*>"#)
        .unwrap()
        .find(html)
        .expect("page contains Keycloak's login form")
        .as_str();
    let action = Regex::new(r#"\baction="([^"]+)""#)
        .unwrap()
        .captures(form)
        .expect("login form has an action")[1]
        .to_owned();
    action.replace("&amp;", "&")
}

/// Waits for the stack: the BFF is ready once it has reached Keycloak and Redis.
pub async fn wait_for_bff() {
    let http = Client::new();
    for _ in 0..60 {
        if let Ok(response) = http.get(bff("/health/ready")).send().await
            && response.status() == StatusCode::OK
        {
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!(
        "BFF at {} did not become ready; is the compose stack up?",
        bff_base()
    );
}

pub async fn redis() -> MultiplexedConnection {
    let url = std::env::var("E2E_REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into());
    redis::Client::open(url)
        .expect("E2E_REDIS_URL is a Redis URL")
        .get_multiplexed_async_connection()
        .await
        .expect("Redis is reachable")
}

/// Mirrors the BFF's key hashing, so tests can find the entry behind a cookie value.
pub fn hash_key(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, value.as_bytes()).as_ref())
}

/// Mirrors the BFF's `sealed::open`: decrypts a Redis value with the cookie value it belongs to.
/// `label` is the purpose, e.g. `b"bff:pending-login:v1"`.
pub fn open_sealed(secret: &str, label: &'static [u8], sealed: &[u8]) -> Option<Vec<u8>> {
    let prk = Salt::new(ring::hkdf::HKDF_SHA256, b"bff-sealed-v1").extract(secret.as_bytes());
    let info = [label];
    let okm = prk.expand(&info, &CHACHA20_POLY1305).ok()?;
    let key = LessSafeKey::new(UnboundKey::from(okm));
    let (nonce, ciphertext) = sealed.split_at_checked(NONCE_LEN)?;
    let mut buffer = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(
            Nonce::try_assume_unique_for_key(nonce).ok()?,
            Aad::from(label),
            &mut buffer,
        )
        .ok()?;
    Some(plaintext.to_vec())
}
