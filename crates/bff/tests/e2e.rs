#![cfg(feature = "e2e")]

mod support;

use redis::AsyncCommands;
use reqwest::StatusCode;
use serde_json::Value;

use crate::support::{
    Browser, bff, hash_key, location, login_url, open_sealed, query_param, redis, set_cookie,
    sign_in, sign_in_until_callback, wait_for_bff,
};

async fn pending_login(state: &str) -> (Option<Value>, i64) {
    let mut redis = redis().await;
    let key = format!("bff:login:{}", hash_key(state));
    let raw: Option<Vec<u8>> = redis.get(&key).await.unwrap();
    let ttl: i64 = redis.ttl(&key).await.unwrap();
    let pending = raw.map(|r| {
        let plaintext =
            open_sealed(state, b"bff:pending-login:v1", &r).expect("should be sealed with state");
        serde_json::from_slice(&plaintext).unwrap()
    });
    (pending, ttl)
}

async fn raw_session(sid: &str) -> Option<Vec<u8>> {
    let mut redis = redis().await;
    redis
        .get(format!("bff:session:{}", hash_key(sid)))
        .await
        .unwrap()
}

async fn session_ttl(sid: &str) -> i64 {
    let mut redis = redis().await;
    redis
        .ttl(format!("bff:session:{}", hash_key(sid)))
        .await
        .unwrap()
}

#[tokio::test]
async fn given_a_login_request_when_handled_then_it_redirects_to_keycloak_with_pkce() {
    wait_for_bff().await;
    let mut browser = Browser::new();

    let response = browser.get(&login_url("/dashboard")).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let authorize = location(&response);
    assert!(
        authorize.path().ends_with("/protocol/openid-connect/auth"),
        "{authorize}"
    );

    assert_eq!(
        query_param(&authorize, "response_type").as_deref(),
        Some("code")
    );

    assert_eq!(query_param(&authorize, "client_id").as_deref(), Some("bff"));
    assert_eq!(
        query_param(&authorize, "code_challenge_method").as_deref(),
        Some("S256")
    );
    assert_eq!(
        query_param(&authorize, "code_challenge").map(|c| c.len()),
        Some(43)
    );

    assert!(
        query_param(&authorize, "scope")
            .unwrap()
            .split(' ')
            .any(|s| s == "openid")
    );

    assert!(query_param(&authorize, "nonce").is_some());
    let state = query_param(&authorize, "state").expect("state should exist");
    let cookie = set_cookie(&response, "__Host-bff-login").expect("there should be a bff cookie");
    assert!(
        cookie.starts_with(&format!("__Host-bff-login={state};")),
        "{cookie}"
    );
    let lower = cookie.to_ascii_lowercase();
    for attribute in [
        "httponly",
        "secure",
        "samesite=lax",
        "max-age=300",
        "path=/",
    ] {
        assert!(
            lower.contains(attribute),
            "{cookie} should have {attribute}"
        );
    }

    let (pending, ttl) = pending_login(&state).await;
    let pending = pending.expect("pending login should exist");
    assert_eq!(pending["return_to"], "/dashboard");
    assert!((1..=300).contains(&ttl), "ttl {ttl}");
}

#[tokio::test]
async fn given_off_site_return_urls_when_logging_in_then_the_url_should_fall_back_to_root() {
    wait_for_bff().await;
    for raw in [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "/\t/evil.com",
        "javascript:alert(1)",
    ] {
        let mut browser = Browser::new();
        let response = browser.get(&login_url(raw)).await;
        let state = query_param(&location(&response), "state").unwrap();

        let (pending, _) = pending_login(&state).await;
        assert_eq!(
            pending.unwrap()["return_to"],
            "/",
            "should not accept {raw:?}"
        );
    }
}

#[tokio::test]
async fn given_no_session_when_reading_session_then_it_should_be_unauthorized() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    let response = browser.get(bff("/auth/session").as_str()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn given_valid_credentials_when_logging_in_then_it_should_succeed_with_a_session() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    let callback = sign_in(&mut browser, "/dashboard").await;

    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&callback).path(), "/dashboard");

    let session_cookie = set_cookie(&callback, "__Host-bff").expect("the cookie should exist");
    assert!(
        session_cookie
            .to_ascii_lowercase()
            .contains("samesite=strict"),
        "{session_cookie}"
    );
    assert!(
        browser.cookie("__Host-bff-login").is_none(),
        "login cookie should be cleared"
    );

    let sid = browser.cookie("__Host-bff").unwrap().to_owned();
    let ttl = session_ttl(&sid).await;
    assert!((1..=3_600).contains(&ttl), "session ttl {ttl}");

    let my_session = browser.get(bff("/auth/session").as_str()).await;
    assert_eq!(my_session.status(), StatusCode::OK);
    let body: Value = my_session.json().await.unwrap();
    assert!(
        body["sub"].as_str().is_some_and(|s| !s.is_empty()),
        "sub should exist and not blank"
    );
}

#[tokio::test]
async fn given_a_used_callback_when_replayed_then_it_should_be_rejected() {
    wait_for_bff().await;
    let mut browser = Browser::new();

    let callback = sign_in_until_callback(&mut browser, "/").await;
    let login_cookie = browser.cookie("__Host-bff-login").unwrap().to_owned();
    assert_eq!(
        browser.get(callback.as_str()).await.status(),
        StatusCode::SEE_OTHER
    );

    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(callback.as_str())
        .header("cookie", format!("__Host-bff-login={login_cookie}"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn given_another_browser_when_it_opens_the_callback_then_it_should_be_rejected_but_the_original_works()
 {
    wait_for_bff().await;
    let mut browser = Browser::new();
    let callback = sign_in_until_callback(&mut browser, "/").await;

    let mut other = Browser::new();

    assert_eq!(
        other.get(callback.as_str()).await.status(),
        StatusCode::UNAUTHORIZED
    );

    assert_eq!(
        browser.get(callback.as_str()).await.status(),
        StatusCode::SEE_OTHER
    );
}

#[tokio::test]
async fn given_a_tampered_state_when_calling_back_then_it_should_be_rejected() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    let mut callback = sign_in_until_callback(&mut browser, "/").await;

    let code = query_param(&callback, "code").unwrap();
    callback
        .query_pairs_mut()
        .clear()
        .append_pair("code", &code)
        .append_pair("state", "tampered");

    assert_eq!(
        browser.get(callback.as_str()).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn given_an_existing_session_when_signing_in_again_then_the_old_session_is_ended() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let first = browser.cookie("__Host-bff").unwrap().to_owned();

    sign_in(&mut browser, "/").await;
    let second = browser.cookie("__Host-bff").unwrap().to_owned();

    assert_ne!(first, second, "a fresh session id is issued");
    assert_eq!(session_ttl(&first).await, -2, "old session key is deleted");
    assert!(session_ttl(&second).await > 0);
}

#[tokio::test]
async fn given_a_session_when_stored_then_redis_holds_only_the_ciphertext_bound_to_its_cookie() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;

    let sid = browser.cookie("__Host-bff").unwrap().to_owned();
    let raw = raw_session(&sid)
        .await
        .expect("The session should be stored");
    assert!(
        serde_json::from_slice::<Value>(&raw).is_err(),
        "stored value should not be a raw JSON"
    );

    assert!(!String::from_utf8_lossy(&raw).contains("access_token"));
    let plaintext =
        open_sealed(&sid, b"bff:session:v1", &raw).expect("The session should be decrypted");

    let session: Value = serde_json::from_slice(&plaintext).unwrap();
    assert!(
        session["access_token"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert!(open_sealed("other-sid", b"bff:session:v1", &raw).is_none());
}

#[tokio::test]
async fn given_a_logout_without_the_csrf_header_when_executing_then_it_should_be_forbidden() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;

    let response = browser.post(bff("/auth/logout").as_str(), &[]).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let session_response = browser.get(bff("/auth/session").as_str()).await;
    assert_eq!(
        session_response.status(),
        StatusCode::OK,
        "The session should still be there"
    );
}

#[tokio::test]
async fn given_a_session_when_logging_out_then_it_ends_and_keycloak_logout_is_returned() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let sid = browser.cookie("__Host-bff").unwrap().to_owned();

    let response = browser
        .post(bff("/auth/logout").as_str(), &[("x-bff-csrf", "1")])
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let cleared = set_cookie(&response, "__Host-bff").expect("session cookie is cleared");
    assert!(
        cleared.to_ascii_lowercase().contains("max-age=0"),
        "{cleared}"
    );
    let body: Value = response.json().await.unwrap();
    let logout_url = reqwest::Url::parse(body["logoutUrl"].as_str().unwrap()).unwrap();
    assert!(
        logout_url
            .path()
            .ends_with("/protocol/openid-connect/logout"),
        "{logout_url}"
    );
    assert!(query_param(&logout_url, "id_token_hint").is_some());

    assert!(raw_session(&sid).await.is_none(), "session key is deleted");
    let session_response = browser.get(bff("/auth/session").as_str()).await;
    assert_eq!(session_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn given_a_running_app_when_probing_health_then_live_and_ready_should_succeed() {
    wait_for_bff().await;
    let mut browser = Browser::new();

    assert_eq!(
        browser.get(bff("/health").as_str()).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        browser.get(bff("/health/ready").as_str()).await.status(),
        StatusCode::OK
    );
}
