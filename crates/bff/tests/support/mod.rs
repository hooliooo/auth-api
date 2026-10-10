//! Helpers for the e2e tests: a cookie-keeping browser, sign-in, and direct access to Redis,
//! Keycloak and the test helper service.

use std::{collections::HashMap, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::aio::MultiplexedConnection;
use regex::Regex;
use reqwest::{
    Client, Method, RequestBuilder, Response, StatusCode, Url,
    header::{COOKIE, LOCATION, SET_COOKIE},
    redirect::Policy,
};
use ring::{
    aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    digest::{SHA256, digest},
    hkdf::Salt,
    rand::{SecureRandom, SystemRandom},
};
use serde_json::Value;

/// The dev realm's test user.
pub const USERNAME: &str = "alice";
/// [`USERNAME`]'s password.
pub const PASSWORD: &str = "test";

/// Lets one sign-in at a time reach Keycloak: its brute-force protection briefly disables a
/// user whose sign-ins overlap.
static SIGN_IN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The BFF's base URL (`E2E_BFF_URL`, default `http://localhost:5100`).
pub fn bff_base() -> Url {
    let base_url = std::env::var("E2E_BFF_URL").unwrap_or_else(|_| "http://localhost:5100".into());
    Url::parse(&base_url).expect("E2E_BFF_URL should be a Url")
}

/// The BFF URL for `path`.
pub fn bff(path: &str) -> Url {
    bff_base().join(path).expect("Paths should join the Url")
}

/// A browser stand-in: one cookie jar for every site, no automatic redirects.
pub struct Browser {
    /// Client without redirects or cookie handling of its own.
    http: Client,
    /// Cookies by name, as the sites set them.
    jar: HashMap<String, String>,
    /// A made-up address sent as [`CLIENT_IP_HEADER`], so every browser has its own
    /// rate-limit bucket.
    pub client_ip: String,
}

/// The header the test stack's BFF reads client addresses from (`CLIENT_IP_HEADER`).
pub const CLIENT_IP_HEADER: &str = "cf-connecting-ip";

impl Browser {
    /// A browser with an empty jar and a random client address.
    pub fn new() -> Self {
        let http = Client::builder()
            .redirect(Policy::none())
            // Above the slow-stream test's 12 s, so the client is never what cuts it off.
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Client should build");
        let mut octets = [0u8; 3];
        SystemRandom::new()
            .fill(&mut octets)
            .expect("random source");
        Self {
            http,
            jar: HashMap::default(),
            client_ip: format!("10.{}.{}.{}", octets[0], octets[1], octets[2]),
        }
    }

    /// `GET` to `url` with the jar's cookies.
    pub async fn get(&mut self, url: &str) -> Response {
        let request = self.http.get(url);
        self.send(request).await
    }

    /// A `fetch()`-style `POST` to `url` without body, with extra `headers`.
    pub async fn post(&mut self, url: &str, headers: &[(&str, &str)]) -> Response {
        let mut request = self.http.post(url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        self.send(request).await
    }

    /// Any `method` on `url`, with extra `headers` and an optional `body`; for calls through the
    /// proxy.
    pub async fn request(
        &mut self,
        method: Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> Response {
        let mut request = self.http.request(method, url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(body) = body {
            request = request.body(body.to_owned());
        }
        self.send(request).await
    }

    /// `POST` to `url` with `form` URL-encoded, as an HTML form submits.
    pub async fn post_form(&mut self, url: &str, form: &[(&str, &str)]) -> Response {
        let request = self.http.post(url).form(form);
        self.send(request).await
    }

    /// The value of cookie `name`, if set.
    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.jar.get(name).map(String::as_str)
    }

    /// Whether any cookie's name starts with `prefix`.
    pub fn has_cookie_starting_with(&self, prefix: &str) -> bool {
        self.jar.keys().any(|name| name.starts_with(prefix))
    }

    /// Sends `request` with the jar's cookies and stores the cookies the response sets.
    async fn send(&mut self, request: RequestBuilder) -> Response {
        let request = request.header(CLIENT_IP_HEADER, &self.client_ip);
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

/// Every `Set-Cookie` header of `response`.
pub fn set_cookies(response: &Response) -> Vec<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect()
}

/// The `Set-Cookie` header of `response` for cookie `name`.
pub fn set_cookie(response: &Response, name: &str) -> Option<String> {
    set_cookies(response)
        .into_iter()
        .find(|c| c.starts_with(&format!("{name}=")))
}

/// The redirect target of `response`, resolved against the BFF; panics without one.
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

/// Query parameter `name` of `url`.
pub fn query_param(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// The BFF's sign-in URL returning to `return_url`.
pub fn login_url(return_url: &str) -> String {
    let mut url = bff("/auth/login");
    url.query_pairs_mut().append_pair("returnUrl", return_url);
    url.to_string()
}

/// Signs `browser` in at Keycloak, returning to `return_url`, and stops before the BFF's
/// callback; returns the callback URL.
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

/// A complete sign-in of `browser`, returning to `return_url`; returns the callback's response.
pub async fn sign_in(browser: &mut Browser, return_url: &str) -> Response {
    let callback = sign_in_until_callback(browser, return_url).await;
    browser.get(callback.as_str()).await
}

/// Where Keycloak's login form in `html` posts to.
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

/// Waits up to a minute for the BFF to report ready.
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

/// A connection to the test stack's Redis (`E2E_REDIS_URL`).
pub async fn redis() -> MultiplexedConnection {
    let url = std::env::var("E2E_REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into());
    redis::Client::open(url)
        .expect("E2E_REDIS_URL is a Redis URL")
        .get_multiplexed_async_connection()
        .await
        .expect("Redis is reachable")
}

/// Mirrors the BFF's key hashing: the Redis key part for `value`.
pub fn hash_key(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, value.as_bytes()).as_ref())
}

/// Mirrors the BFF's `sealed::open`: decrypts `sealed` with the key for `secret` and
/// purpose `label`.
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

/// The BFF's sealing key for `secret` and purpose `label`.
fn sealing_key(secret: &str, label: &'static [u8]) -> LessSafeKey {
    let prk = Salt::new(ring::hkdf::HKDF_SHA256, b"bff-sealed-v1").extract(secret.as_bytes());
    let info = [label];
    let okm = prk
        .expand(&info, &CHACHA20_POLY1305)
        .expect("valid key length");
    LessSafeKey::new(UnboundKey::from(okm))
}

/// Mirrors the BFF's `sealed::seal`: encrypts `plaintext` for `secret` and purpose `label`.
pub fn seal(secret: &str, label: &'static [u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce).expect("random source");
    let mut buffer = plaintext.to_vec();
    sealing_key(secret, label)
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(label),
            &mut buffer,
        )
        .expect("sealing works");
    let mut sealed = nonce.to_vec();
    sealed.extend(buffer);
    sealed
}

/// The sealing purpose of sessions.
pub const SESSION_LABEL: &[u8] = b"bff:session:v1";

/// Redis key of session `sid`.
fn session_key(sid: &str) -> String {
    format!("bff:session:{}", hash_key(sid))
}

/// The decrypted session `sid`, if it exists.
pub async fn read_session(sid: &str) -> Option<Value> {
    let mut redis = redis().await;
    let raw: Option<Vec<u8>> = redis::AsyncCommands::get(&mut redis, session_key(sid))
        .await
        .unwrap();
    raw.map(|raw| {
        let plaintext = open_sealed(sid, SESSION_LABEL, &raw).expect("session opens");
        serde_json::from_slice(&plaintext).unwrap()
    })
}

/// Replaces session `sid` with `session`, keeping its expiry; used to force a refresh.
pub async fn write_session(sid: &str, session: &Value) {
    let mut redis = redis().await;
    let sealed = seal(sid, SESSION_LABEL, &serde_json::to_vec(session).unwrap());
    redis::cmd("SET")
        .arg(session_key(sid))
        .arg(sealed)
        .arg("KEEPTTL")
        .query_async::<()>(&mut redis)
        .await
        .unwrap();
}

/// The hashed session ids indexed under Keycloak session `keycloak_sid`.
pub async fn index_members(keycloak_sid: &str) -> Vec<String> {
    let mut redis = redis().await;
    redis::AsyncCommands::smembers(&mut redis, format!("bff:iam-sid:{keycloak_sid}"))
        .await
        .unwrap()
}

/// Keycloak's URL as the tests reach it (`E2E_KEYCLOAK_URL`).
fn keycloak_base() -> String {
    std::env::var("E2E_KEYCLOAK_URL").unwrap_or_else(|_| "http://localhost:8080".into())
}

/// Ends Keycloak session `keycloak_sid` through the admin API; Keycloak then sends the BFF a
/// back-channel logout. Other sessions of the user are untouched.
pub async fn end_keycloak_session(keycloak_sid: &str) {
    let token = keycloak_admin_token().await;
    let status = Client::new()
        .delete(format!(
            "{}/admin/realms/test/sessions/{keycloak_sid}",
            keycloak_base()
        ))
        .bearer_auth(token)
        .send()
        .await
        .expect("Keycloak is reachable")
        .status();
    assert_eq!(status, StatusCode::NO_CONTENT, "Keycloak ends the session");
}

/// Polls `check` for up to 5 seconds; panics naming `what` if it never holds.
pub async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..50 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting until {what}");
}

/// Mirrors the BFF's `cookie::login_cookie`: the login cookie name for `state`.
pub fn login_cookie_name(state: &str) -> String {
    format!("__Host-bff-login-{}", &hash_key(state)[..16])
}

/// The current time in Unix seconds.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The test helper service's URL for `path` (`E2E_HELPERS_URL`).
pub fn helpers_url(path: &str) -> String {
    let base = std::env::var("E2E_HELPERS_URL").unwrap_or_else(|_| "http://localhost:5199".into());
    format!("{base}{path}")
}

/// Makes the Keycloak proxy answer `status` once, to the first request whose body contains
/// `matches`.
pub async fn arm_keycloak_fault(matches: &str, status: u16) {
    let response = Client::new()
        .post(helpers_url("/faults"))
        .json(&serde_json::json!({ "matches": matches, "status": status }))
        .send()
        .await
        .expect("the test helpers are reachable; is docker-compose.test.yml in use?");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

/// The back-channel logout tokens the recorder has passed on to the BFF.
pub async fn recorded_logout_tokens() -> Vec<String> {
    Client::new()
        .get(helpers_url("/relay/logout-tokens"))
        .send()
        .await
        .expect("the test helpers are reachable")
        .json()
        .await
        .unwrap()
}

/// The payload of JWT `token`, without checking its signature; for reading test tokens.
pub fn unverified_payload(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("a JWT");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

/// An access token for Keycloak's admin API.
async fn keycloak_admin_token() -> String {
    let token: Value = Client::new()
        .post(format!(
            "{}/realms/master/protocol/openid-connect/token",
            keycloak_base()
        ))
        .form(&[
            ("grant_type", "password"),
            ("client_id", "admin-cli"),
            ("username", "admin"),
            ("password", "test"),
        ])
        .send()
        .await
        .expect("Keycloak is reachable")
        .json()
        .await
        .expect("admin token");
    token["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned()
}

/// Points the `bff` client's back-channel logouts at `url`; returns the previous address.
pub async fn set_backchannel_logout_url(url: &str) -> String {
    let http = Client::new();
    let token = keycloak_admin_token().await;
    let clients_url = format!("{}/admin/realms/test/clients", keycloak_base());
    let clients: Vec<Value> = http
        .get(format!("{clients_url}?clientId=bff"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut client = clients.into_iter().next().expect("the bff client exists");
    let previous = client["attributes"]["backchannel.logout.url"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    client["attributes"]["backchannel.logout.url"] = url.into();
    let id = client["id"].as_str().unwrap().to_owned();
    let status = http
        .put(format!("{clients_url}/{id}"))
        .bearer_auth(&token)
        .json(&client)
        .send()
        .await
        .unwrap()
        .status();
    assert!(status.is_success(), "updating the bff client: {status}");
    previous
}

/// Keycloak's status for exchanging `refresh_token` as the BFF would: 200 if still valid.
pub async fn keycloak_refresh_status(refresh_token: &str) -> StatusCode {
    Client::new()
        .post(format!(
            "{}/realms/test/protocol/openid-connect/token",
            keycloak_base()
        ))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", "bff"),
            ("client_secret", "bff.secret"),
        ])
        .send()
        .await
        .expect("Keycloak is reachable")
        .status()
}
