//! Helpers for the e2e tests: a cookie-keeping browser, sign-in, and direct access to Redis,
//! Keycloak and the test helpers, all in the local cluster (`dev/k8s/up.sh --e2e`).
//!
//! The tests reach the BFFs and Keycloak through the ingress, at their public names, like a
//! browser does; they resolve those names to the ingress themselves (`E2E_INGRESS_ADDR`), so no
//! hosts-file entries are needed. Redis, the BFF's metrics and the helpers' controls are on
//! ports the cluster maps to this machine for the tests only.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use redis::aio::MultiplexedConnection;
use regex::Regex;
use reqwest::{
    Client, ClientBuilder, Method, RequestBuilder, Response, StatusCode, Url,
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
/// The BFF under test's public address.
const BFF_HOST: &str = "auth-api";
/// The address of the BFF that treats Keycloak as any OpenID Connect provider.
const OIDC_BFF_HOST: &str = "auth-api-oidc";
/// The address of the BFF that trusts no proxy.
const UNTRUSTED_BFF_HOST: &str = "auth-api-untrusted";
/// Keycloak's public address, also its issuer's host.
const KEYCLOAK_HOST: &str = "keycloak-api";
/// The Keycloak client the tests administer the realm with (realm-admin in the test realm).
const ADMIN_CLIENT_ID: &str = "end.to.end.client";

/// Lets one sign-in at a time reach Keycloak: its brute-force protection briefly disables a
/// user whose sign-ins overlap.
static SIGN_IN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Where the ingress listens on this machine (`E2E_INGRESS_ADDR`, default `127.0.0.1:443`).
fn ingress() -> SocketAddr {
    std::env::var("E2E_INGRESS_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:443".into())
        .parse()
        .expect("E2E_INGRESS_ADDR should be an address and port")
}

/// A client builder that sends every public name the tests use to the ingress. TLS is checked
/// as usual: the local CA is trusted on this machine (`mkcert -install`).
pub fn http_builder() -> ClientBuilder {
    [BFF_HOST, OIDC_BFF_HOST, UNTRUSTED_BFF_HOST, KEYCLOAK_HOST]
        .into_iter()
        .fold(Client::builder(), |builder, host| {
            builder.resolve(host, ingress())
        })
}

/// A client for one-off calls: through the ingress, without following redirects.
pub fn http() -> Client {
    http_builder()
        .redirect(Policy::none())
        .build()
        .expect("Client should build")
}

/// `https://<host>/`.
fn https(host: &str) -> Url {
    Url::parse(&format!("https://{host}/")).expect("a host makes a URL")
}

/// The BFF's base URL.
pub fn bff_base() -> Url {
    https(BFF_HOST)
}

/// The BFF URL for `path`.
pub fn bff(path: &str) -> Url {
    bff_base().join(path).expect("Paths should join the Url")
}

/// The base URL of the BFF that treats Keycloak as any OpenID Connect provider.
pub fn oidc_bff_base() -> Url {
    https(OIDC_BFF_HOST)
}

/// The URL for `path` at the BFF that trusts no proxy.
pub fn untrusted_bff(path: &str) -> Url {
    https(UNTRUSTED_BFF_HOST)
        .join(path)
        .expect("Paths should join the Url")
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

/// The header the test BFFs read client addresses from (`CLIENT_IP_HEADER`); the ingress
/// passes it through untouched, as it would Cloudflare's.
pub const CLIENT_IP_HEADER: &str = "cf-connecting-ip";
/// The header the app sends on every call to `/api/*` and `/auth/*` (the BFF's CSRF defense).
pub const CSRF_HEADER: &str = "x-bff-csrf";
/// The BFF's session cookie.
pub const SESSION_COOKIE: &str = "__Host-Http-bff";

impl Browser {
    /// A browser with an empty jar and a random client address.
    pub fn new() -> Self {
        let http = http_builder()
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

    /// A navigation to `url` (a link, a redirect, the address bar): `GET` with the jar's cookies
    /// and nothing an app's script would add.
    pub async fn get(&mut self, url: &str) -> Response {
        let request = self.http.get(url);
        self.send(request).await
    }

    /// The app's `fetch()` of `url`: `GET` with the CSRF header, as the app sends on every call.
    pub async fn fetch(&mut self, url: &str) -> Response {
        self.request(Method::GET, url, &[], None).await
    }

    /// A `fetch()`-style `POST` to `url` without body, with exactly the extra `headers`; the CSRF
    /// header only if they include it.
    pub async fn post(&mut self, url: &str, headers: &[(&str, &str)]) -> Response {
        let mut request = self.http.post(url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        self.send(request).await
    }

    /// The app's call of any `method` on `url`, with the CSRF header, extra `headers` and an
    /// optional `body`; for calls through the proxy.
    pub async fn request(
        &mut self,
        method: Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> Response {
        let mut with_csrf = vec![(CSRF_HEADER, "1")];
        with_csrf.extend_from_slice(headers);
        self.request_without_csrf_header(method, url, &with_csrf, body)
            .await
    }

    /// [`Self::request`] without the CSRF header: what a page of another origin could send.
    pub async fn request_without_csrf_header(
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
            let cookies = self
                .jar
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            request.header(COOKIE, cookies)
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
    login_url_at(&bff_base(), return_url)
}

/// The sign-in URL of the BFF at `base`, returning to `return_url`.
fn login_url_at(base: &Url, return_url: &str) -> String {
    let mut url = base.join("/auth/login").expect("Paths should join the Url");
    url.query_pairs_mut().append_pair("returnUrl", return_url);
    url.to_string()
}

/// Signs `browser` in at Keycloak, returning to `return_url`, and stops before the BFF's
/// callback; returns the callback URL.
pub async fn sign_in_until_callback(browser: &mut Browser, return_url: &str) -> Url {
    sign_in_until_callback_at(browser, &bff_base(), return_url).await
}

/// [`sign_in_until_callback`] for the BFF at `base`.
async fn sign_in_until_callback_at(browser: &mut Browser, base: &Url, return_url: &str) -> Url {
    let _one_at_a_time = SIGN_IN.lock().await;
    let login = browser.get(&login_url_at(base, return_url)).await;
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

    location(&submitted)
}

/// A complete sign-in of `browser`, returning to `return_url`; returns the callback's response.
pub async fn sign_in(browser: &mut Browser, return_url: &str) -> Response {
    sign_in_at(browser, &bff_base(), return_url).await
}

/// [`sign_in`] at the BFF at `base`.
pub async fn sign_in_at(browser: &mut Browser, base: &Url, return_url: &str) -> Response {
    let callback = sign_in_until_callback_at(browser, base, return_url).await;
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

/// Waits up to a minute for the BFF to report ready, and for Keycloak to know every test BFF.
pub async fn wait_for_bff() {
    wait_for_bff_at(&bff_base()).await;
}

/// Waits up to a minute for the BFF at `base` to report ready, and for Keycloak to know every
/// test BFF.
pub async fn wait_for_bff_at(base: &Url) {
    let http = http();
    let ready = base
        .join("/health/ready")
        .expect("Paths should join the Url");
    let mut is_ready = false;
    for _ in 0..60 {
        if let Ok(response) = http.get(ready.clone()).send().await
            && response.status() == StatusCode::OK
        {
            is_ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(
        is_ready,
        "BFF at {base} did not become ready; is the cluster up with dev/k8s/up.sh --e2e?"
    );
    register_test_bffs().await;
}

/// Lets the BFF that treats Keycloak as any OpenID Connect provider sign users in: adds its
/// addresses to the `bff` client, once per test run and before any test changes the client.
/// The realm setup only registers the BFF's own address, and may have run without the tests.
async fn register_test_bffs() {
    static REGISTERED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    REGISTERED
        .get_or_init(|| async {
            let base = oidc_bff_base();
            let callback = base.join("/auth/callback").unwrap().to_string();
            update_bff_client(|client| {
                let uris = client["redirectUris"]
                    .as_array_mut()
                    .expect("the client has redirect URIs");
                if !uris.iter().any(|uri| uri == callback.as_str()) {
                    uris.push(callback.clone().into());
                }
                let attributes = &mut client["attributes"];
                let post_logout = attributes["post.logout.redirect.uris"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                if !post_logout.split("##").any(|uri| uri == base.as_str()) {
                    attributes["post.logout.redirect.uris"] = if post_logout.is_empty() {
                        base.to_string()
                    } else {
                        format!("{post_logout}##{base}")
                    }
                    .into();
                }
            })
            .await;
        })
        .await;
}

/// A connection to the cluster's Redis (`E2E_REDIS_URL`, default `redis://127.0.0.1:16379`).
pub async fn redis() -> MultiplexedConnection {
    let url = std::env::var("E2E_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:16379".into());
    redis::Client::open(url)
        .expect("E2E_REDIS_URL is a Redis URL")
        .get_multiplexed_async_connection()
        .await
        .expect("Redis is reachable; is the cluster up with dev/k8s/up.sh --e2e?")
}

/// Mirrors the BFF's key hashing: the Redis key part for `value`.
pub fn hash_key(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, value.as_bytes()).as_ref())
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

/// Mirrors the BFF's `sealed::open`: decrypts `sealed` with the key for `secret` and
/// purpose `label`.
pub fn open_sealed(secret: &str, label: &'static [u8], sealed: &[u8]) -> Option<Vec<u8>> {
    let (nonce, ciphertext) = sealed.split_at_checked(NONCE_LEN)?;
    let mut buffer = ciphertext.to_vec();
    let plaintext = sealing_key(secret, label)
        .open_in_place(
            Nonce::try_assume_unique_for_key(nonce).ok()?,
            Aad::from(label),
            &mut buffer,
        )
        .ok()?;
    Some(plaintext.to_vec())
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

/// Keycloak's URL, as browsers and the BFF reach it.
fn keycloak_base() -> String {
    format!("https://{KEYCLOAK_HOST}")
}

/// Ends Keycloak session `keycloak_sid` through the admin API; Keycloak then sends the BFF a
/// back-channel logout. Other sessions of the user are untouched.
pub async fn end_keycloak_session(keycloak_sid: &str) {
    let token = keycloak_admin_token().await;
    let status = http()
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
    format!("__Host-Http-bff-login-{}", &hash_key(state)[..16])
}

/// The current time in Unix seconds.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The test helpers' URL for `path` (`E2E_HELPERS_URL`, default `http://127.0.0.1:19199`).
pub fn helpers_url(path: &str) -> String {
    let base = std::env::var("E2E_HELPERS_URL").unwrap_or_else(|_| "http://127.0.0.1:19199".into());
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
        .expect("the test helpers are reachable; is the cluster up with dev/k8s/up.sh --e2e?");
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

/// The admin client's secret: `E2E_CLIENT_SECRET`, or else the one the cluster generated, read
/// with kubectl from the cluster's own context.
fn admin_client_secret() -> &'static str {
    static SECRET: OnceLock<String> = OnceLock::new();
    SECRET.get_or_init(|| {
        if let Ok(secret) = std::env::var("E2E_CLIENT_SECRET") {
            return secret;
        }
        let output = std::process::Command::new("kubectl")
            .args([
                "--context",
                "kind-auth-api",
                "-n",
                "auth-api",
                "get",
                "secret",
                "keycloak-clients",
                "-o",
                "jsonpath={.data.end-to-end-client-secret}",
            ])
            .output()
            .expect("kubectl runs; or set E2E_CLIENT_SECRET");
        assert!(
            output.status.success(),
            "reading the e2e client's secret: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(STANDARD.decode(output.stdout.trim_ascii()).expect("base64"))
            .expect("the secret is text")
    })
}

/// An access token for Keycloak's admin API of the test realm.
async fn keycloak_admin_token() -> String {
    let token: Value = http()
        .post(format!(
            "{}/realms/test/protocol/openid-connect/token",
            keycloak_base()
        ))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", ADMIN_CLIENT_ID),
            ("client_secret", admin_client_secret()),
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

/// Reads the `bff` client, lets `change` edit it, and saves it.
async fn update_bff_client(change: impl FnOnce(&mut Value)) {
    let http = http();
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
    change(&mut client);
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
}

/// Points the `bff` client's back-channel logouts at `url`; returns the previous address.
pub async fn set_backchannel_logout_url(url: &str) -> String {
    let mut previous = String::new();
    update_bff_client(|client| {
        previous = client["attributes"]["backchannel.logout.url"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        client["attributes"]["backchannel.logout.url"] = url.into();
    })
    .await;
    previous
}

/// Keycloak's status for exchanging `refresh_token` as the BFF would: 200 if still valid.
pub async fn keycloak_refresh_status(refresh_token: &str) -> StatusCode {
    let assertion = client_assertion(&dev_client_key(), &bff_client_key_id().await, 60);
    token_request(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", "bff"),
        ("client_assertion_type", JWT_BEARER),
        ("client_assertion", &assertion),
    ])
    .await
    .0
}

/// The `client_assertion_type` of a signed JWT client assertion.
pub const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// A request to the test realm's token endpoint with `form`; its status and its `error`, if any.
pub async fn token_request(form: &[(&str, &str)]) -> (StatusCode, Option<String>) {
    let response = http()
        .post(format!(
            "{}/realms/test/protocol/openid-connect/token",
            keycloak_base()
        ))
        .form(form)
        .send()
        .await
        .expect("Keycloak is reachable");
    let status = response.status();
    let body: Value = response.json().await.unwrap_or_default();
    (status, body["error"].as_str().map(str::to_owned))
}

/// This machine's client key (`dev/client-key.pem`), which `dev/k8s/up.sh` gave the BFFs.
pub fn dev_client_key() -> jsonwebtoken::EncodingKey {
    let pem = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/dev/client-key.pem"))
        .expect("the local client key exists; dev/k8s/up.sh creates it");
    jsonwebtoken::EncodingKey::from_ec_pem(&pem).expect("an EC P-256 key")
}

/// The key id the BFF publishes for its client key.
pub async fn bff_client_key_id() -> String {
    let jwks: Value = http()
        .get(bff("/.well-known/jwks.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    jwks["keys"][0]["kid"]
        .as_str()
        .expect("the BFF publishes its key")
        .to_owned()
}

/// A client assertion for client `bff`, signed with `key` under key id `kid`, expiring
/// `expires_in` seconds from now (negative for one already expired).
pub fn client_assertion(key: &jsonwebtoken::EncodingKey, kid: &str, expires_in: i64) -> String {
    let now = now() as i64;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(kid.to_owned());
    let claims = serde_json::json!({
        "iss": "bff",
        "sub": "bff",
        "aud": format!("{}/realms/test", keycloak_base()),
        "jti": URL_SAFE_NO_PAD.encode(rand_bytes()),
        "iat": now,
        "exp": now + expires_in,
    });
    jsonwebtoken::encode(&header, &claims, key).expect("signing works")
}

/// 16 random bytes.
fn rand_bytes() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    SystemRandom::new().fill(&mut bytes).expect("random source");
    bytes
}

/// The test realm's SSO session idle timeout, which the BFF's sessions follow.
pub async fn keycloak_session_idle_secs() -> u64 {
    let realm: Value = http()
        .get(format!("{}/admin/realms/test", keycloak_base()))
        .bearer_auth(keycloak_admin_token().await)
        .send()
        .await
        .expect("Keycloak is reachable")
        .json()
        .await
        .unwrap();
    realm["ssoSessionIdleTimeout"]
        .as_u64()
        .expect("an idle timeout")
}

/// The status of a `GET` to `path` at the BFF, sent byte for byte over TLS, unlike an HTTP
/// client, which would resolve `..` and `%2e%2e` before sending. `cookie` is the `Cookie`
/// header's value.
pub async fn raw_get_status(path: &str, cookie: &str) -> u16 {
    use rustls::pki_types::ServerName;
    use rustls_platform_verifier::ConfigVerifierExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let config = rustls::ClientConfig::with_platform_verifier().expect("the platform's roots");
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(ingress()).await.unwrap();
    let mut stream = connector
        .connect(ServerName::try_from(BFF_HOST).unwrap(), tcp)
        .await
        .expect("TLS with the ingress");
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {BFF_HOST}\r\nCookie: {cookie}\r\n{CSRF_HEADER}: 1\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    // The ingress may close without TLS's close_notify; what arrived is enough.
    let _ = stream.read_to_end(&mut response).await;
    let status_line = String::from_utf8_lossy(&response);
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("an HTTP status line")
}

/// The ids of Keycloak's live sessions for user `user_id`.
pub async fn keycloak_user_session_ids(user_id: &str) -> Vec<String> {
    let sessions: Vec<Value> = http()
        .get(format!(
            "{}/admin/realms/test/users/{user_id}/sessions",
            keycloak_base()
        ))
        .bearer_auth(keycloak_admin_token().await)
        .send()
        .await
        .expect("Keycloak is reachable")
        .json()
        .await
        .unwrap();
    sessions
        .iter()
        .filter_map(|session| session["id"].as_str().map(str::to_owned))
        .collect()
}

/// Grants (`granted`) or removes realm role `role` for user `username`.
pub async fn set_realm_role(username: &str, role: &str, granted: bool) {
    let http = http();
    let token = keycloak_admin_token().await;
    let realm_url = format!("{}/admin/realms/test", keycloak_base());
    let users: Vec<Value> = http
        .get(format!("{realm_url}/users?username={username}&exact=true"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = users[0]["id"].as_str().expect("the user exists").to_owned();
    let role_representation: Value = http
        .get(format!("{realm_url}/roles/{role}"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mappings = format!("{realm_url}/users/{user_id}/role-mappings/realm");
    let request = if granted {
        http.post(mappings)
    } else {
        http.delete(mappings)
    };
    let status = request
        .bearer_auth(&token)
        .json(&[role_representation])
        .send()
        .await
        .unwrap()
        .status();
    assert!(status.is_success(), "changing {username}'s roles: {status}");
}

/// The BFF's metrics page (`E2E_METRICS_URL`, default `http://127.0.0.1:19100/metrics`).
pub async fn metrics_page() -> String {
    let url = std::env::var("E2E_METRICS_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:19100/metrics".into());
    Client::new()
        .get(url)
        .send()
        .await
        .expect("the metrics address is reachable; is the cluster up with dev/k8s/up.sh --e2e?")
        .text()
        .await
        .unwrap()
}

/// The value of the sample `series` (name and labels, exactly as rendered) on metrics `page`;
/// 0 if it has not been recorded yet.
pub fn metric(page: &str, series: &str) -> f64 {
    page.lines()
        .find_map(|line| line.strip_prefix(series)?.strip_prefix(' '))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0.0)
}
