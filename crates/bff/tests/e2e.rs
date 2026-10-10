#![cfg(feature = "e2e")]

mod support;

use std::time::Instant;

use redis::AsyncCommands;
use reqwest::{Method, StatusCode, header::CACHE_CONTROL};
use serde_json::Value;

use crate::support::{
    Browser, bff, end_keycloak_session, eventually, hash_key, index_members, location, login_url,
    open_sealed, query_param, read_session, redis, set_cookie, sign_in, sign_in_until_callback,
    wait_for_bff, write_session,
};

fn assert_no_store(response: &reqwest::Response, what: &str) {
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "{what} must not be cached"
    );
}

/// The Keycloak session id stored in a BFF session.
async fn keycloak_sid(sid: &str) -> String {
    read_session(sid).await.expect("session exists")["sid"]
        .as_str()
        .expect("Keycloak sent a sid")
        .to_owned()
}

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

    assert_no_store(&callback, "the callback");
    let session_cookie = set_cookie(&callback, "__Host-bff").expect("the cookie should exist");
    let lowered = session_cookie.to_ascii_lowercase();
    assert!(lowered.contains("samesite=strict"), "{session_cookie}");
    assert!(
        lowered.contains("max-age=86400"),
        "the cookie lives for the 24 h cap, not the 1 h idle timeout: {session_cookie}"
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
    assert_no_store(&my_session, "/auth/session");
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
    let first_keycloak_sid = keycloak_sid(&first).await;

    sign_in(&mut browser, "/").await;
    let second = browser.cookie("__Host-bff").unwrap().to_owned();

    assert_ne!(first, second, "a fresh session id is issued");
    assert_eq!(session_ttl(&first).await, -2, "old session key is deleted");
    assert!(session_ttl(&second).await > 0);
    assert!(
        !index_members(&first_keycloak_sid)
            .await
            .contains(&hash_key(&first)),
        "the old session leaves the back-channel index"
    );
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
    let keycloak_sid = keycloak_sid(&sid).await;
    assert!(index_members(&keycloak_sid).await.contains(&hash_key(&sid)));

    let response = browser
        .post(bff("/auth/logout").as_str(), &[("x-bff-csrf", "1")])
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_no_store(&response, "logout");
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
    assert!(
        !index_members(&keycloak_sid).await.contains(&hash_key(&sid)),
        "the session leaves the back-channel index"
    );
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

#[tokio::test]
async fn given_keycloak_ends_the_sign_in_when_it_notifies_the_bff_then_the_session_ends() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let sid = browser.cookie("__Host-bff").unwrap().to_owned();
    let keycloak_sid = keycloak_sid(&sid).await;
    assert!(
        index_members(&keycloak_sid).await.contains(&hash_key(&sid)),
        "sign-in records the session in the back-channel index"
    );

    end_keycloak_session(&keycloak_sid).await;

    eventually("the BFF session is gone", || async {
        raw_session(&sid).await.is_none()
    })
    .await;
    assert!(index_members(&keycloak_sid).await.is_empty());
    let session_response = browser.get(bff("/auth/session").as_str()).await;
    assert_eq!(session_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn given_an_expired_access_token_when_calling_the_api_then_it_is_refreshed_first() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let sid = browser.cookie("__Host-bff").unwrap().to_owned();
    let mut session = read_session(&sid).await.unwrap();
    let old_access_token = session["access_token"].as_str().unwrap().to_owned();
    session["expires_at"] = 0.into();
    write_session(&sid, &session).await;

    let response = browser
        .request(Method::GET, bff("/api/echo/whoami").as_str(), &[], None)
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let echoed: Value = response.json().await.unwrap();
    let refreshed = read_session(&sid)
        .await
        .expect("session survives the refresh");
    let new_access_token = refreshed["access_token"].as_str().unwrap();
    assert_ne!(new_access_token, old_access_token, "a new access token");
    assert!(refreshed["expires_at"].as_u64().unwrap() > 0);
    assert_eq!(
        echoed["headers"]["authorization"],
        format!("Bearer {new_access_token}"),
        "the API receives the refreshed token"
    );
}

#[tokio::test]
async fn given_a_refresh_token_keycloak_rejects_when_calling_the_api_then_the_session_ends() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let sid = browser.cookie("__Host-bff").unwrap().to_owned();
    let keycloak_sid = keycloak_sid(&sid).await;
    let mut session = read_session(&sid).await.unwrap();
    session["expires_at"] = 0.into();
    session["refresh_token"] = "not-a-refresh-token".into();
    write_session(&sid, &session).await;

    let response = browser
        .request(Method::GET, bff("/api/echo/whoami").as_str(), &[], None)
        .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(raw_session(&sid).await.is_none(), "session is deleted");
    assert!(!index_members(&keycloak_sid).await.contains(&hash_key(&sid)));
}

#[tokio::test]
async fn given_a_session_when_calling_the_api_then_only_the_bearer_is_forwarded() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let sid = browser.cookie("__Host-bff").unwrap().to_owned();
    let access_token = read_session(&sid).await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let response = browser
        .request(
            Method::GET,
            bff("/api/echo/orders?page=2").as_str(),
            &[("authorization", "Bearer forged"), ("x-trace", "keep-me")],
            None,
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get("set-cookie").is_none(),
        "the API's Set-Cookie is stripped"
    );
    assert_eq!(response.headers().get("x-echo").unwrap(), "1");
    let echoed: Value = response.json().await.unwrap();
    assert_eq!(echoed["path"], "/echo/orders", "/api is stripped");
    assert_eq!(echoed["query"], "page=2");
    let headers = &echoed["headers"];
    assert_eq!(headers["authorization"], format!("Bearer {access_token}"));
    assert!(
        headers.get("cookie").is_none(),
        "browser cookies stay at the BFF"
    );
    assert_eq!(
        headers["x-trace"], "keep-me",
        "ordinary headers pass through"
    );
}

#[tokio::test]
async fn given_forged_forwarding_headers_when_calling_the_api_then_only_the_bffs_own_reach_it() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;

    let response = browser
        .request(
            Method::GET,
            bff("/api/echo/orders").as_str(),
            &[
                ("x-forwarded-for", "1.2.3.4"),
                ("forwarded", "for=1.2.3.4;proto=http"),
                ("x-forwarded-host", "evil.example"),
                ("x-forwarded-proto", "http"),
                ("x-real-ip", "1.2.3.4"),
                ("true-client-ip", "1.2.3.4"),
            ],
            None,
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let echoed: Value = response.json().await.unwrap();
    let headers = &echoed["headers"];
    assert_eq!(
        headers["x-forwarded-for"], browser.client_ip,
        "the API sees the client address the BFF determined"
    );
    for forged in [
        "forwarded",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "true-client-ip",
        "cf-connecting-ip",
    ] {
        assert!(
            headers.get(forged).is_none(),
            "{forged} must not reach the API"
        );
    }
}

/// Needs a BFF built with the `rate-limit` feature (the default).
#[cfg(feature = "rate-limit")]
#[tokio::test]
async fn given_too_many_sign_in_starts_from_one_client_then_it_is_limited_but_others_are_not() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    let mut limited = None;
    // The compose stack allows 10 a minute; a minute boundary can reset the count once.
    for _ in 0..25 {
        let response = browser.get(&login_url("/")).await;
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            limited = Some(response);
            break;
        }
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    let limited = limited.expect("the 11th sign-in start in a minute is refused");
    let retry_after: u64 = limited.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&retry_after), "retry-after {retry_after}");

    let mut someone_else = Browser::new();
    assert_eq!(
        someone_else.get(&login_url("/")).await.status(),
        StatusCode::SEE_OTHER,
        "other clients keep their own allowance"
    );
}

#[tokio::test]
async fn given_a_write_through_the_api_when_the_csrf_header_is_missing_then_it_is_forbidden() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;

    let refused = browser
        .request(
            Method::POST,
            bff("/api/echo/orders").as_str(),
            &[],
            Some("{}"),
        )
        .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);

    let accepted = browser
        .request(
            Method::POST,
            bff("/api/echo/orders").as_str(),
            &[("x-bff-csrf", "1"), ("content-type", "application/json")],
            Some(r#"{"item":42}"#),
        )
        .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    let echoed: Value = accepted.json().await.unwrap();
    assert_eq!(echoed["method"], "POST");
    assert_eq!(echoed["body"], r#"{"item":42}"#);
    assert!(
        echoed["headers"].get("x-bff-csrf").is_none(),
        "the CSRF header stays at the BFF"
    );
}

#[tokio::test]
async fn given_no_session_when_calling_the_api_then_it_is_unauthorized() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    let response = browser
        .request(Method::GET, bff("/api/echo/orders").as_str(), &[], None)
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Takes about 12 seconds: longer than the 10-second limit on Keycloak calls.
#[tokio::test]
async fn given_a_slow_streamed_response_when_proxied_then_it_is_not_cut_off() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let started = Instant::now();

    let response = browser
        .request(Method::GET, bff("/api/slow?secs=12").as_str(), &[], None)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("the whole body arrives");

    assert_eq!(body.lines().count(), 12, "{body}");
    assert!(started.elapsed().as_secs() >= 11);
}
