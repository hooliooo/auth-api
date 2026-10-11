//! End-to-end tests against the test stack (`docker-compose.test.yml`); see the README.
#![cfg(feature = "e2e")]

mod support;

use std::time::Instant;

use redis::AsyncCommands;
use reqwest::{Method, StatusCode, header::CACHE_CONTROL};
use serde_json::Value;

use crate::support::{
    Browser, JWT_BEARER, USERNAME, arm_keycloak_fault, bff, bff_client_key_id, client_assertion,
    dev_client_key, end_keycloak_session, eventually, hash_key, index_members,
    keycloak_refresh_status, keycloak_session_idle_secs, keycloak_user_session_ids, location,
    login_cookie_name, login_url, metric, metrics_page, now, open_sealed, query_param,
    raw_get_status, read_session, recorded_logout_tokens, redis, set_backchannel_logout_url,
    set_cookie, set_realm_role, sign_in, sign_in_until_callback, token_request, untrusted_bff,
    unverified_payload, wait_for_bff, write_session,
};

/// Asserts `response` forbids caching; `what` names it in the failure.
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

/// The Keycloak session id stored in BFF session `sid`.
async fn keycloak_sid(sid: &str) -> String {
    read_session(sid).await.expect("session exists")["sid"]
        .as_str()
        .expect("Keycloak sent a sid")
        .to_owned()
}

/// The decrypted pending sign-in for `state`, if any, and its remaining TTL.
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

/// The stored, still encrypted, session `sid`.
async fn raw_session(sid: &str) -> Option<Vec<u8>> {
    let mut redis = redis().await;
    redis
        .get(format!("bff:session:{}", hash_key(sid)))
        .await
        .unwrap()
}

/// Seconds until session `sid` expires; `-2` if it does not exist.
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

    assert_eq!(
        query_param(&authorize, "scope").as_deref(),
        Some("openid"),
        "the BFF's configured scopes (OIDC_SCOPES), nothing more"
    );

    assert!(query_param(&authorize, "nonce").is_some());
    let state = query_param(&authorize, "state").expect("state should exist");
    let name = login_cookie_name(&state);
    let cookie = set_cookie(&response, &name).expect("there should be a login cookie");
    assert!(cookie.starts_with(&format!("{name}={state};")), "{cookie}");
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
        !browser.has_cookie_starting_with("__Host-bff-login"),
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
    let cookie_name = login_cookie_name(&query_param(&callback, "state").unwrap());
    let login_cookie = browser.cookie(&cookie_name).unwrap().to_owned();
    assert_eq!(
        browser.get(callback.as_str()).await.status(),
        StatusCode::SEE_OTHER
    );

    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(callback.as_str())
        .header("cookie", format!("{cookie_name}={login_cookie}"))
        .send()
        .await
        .unwrap();

    assert_login_failed(&response);
}

#[tokio::test]
async fn given_another_browser_when_it_opens_the_callback_then_it_should_be_rejected_but_the_original_works()
 {
    wait_for_bff().await;
    let mut browser = Browser::new();
    let callback = sign_in_until_callback(&mut browser, "/").await;

    let mut other = Browser::new();

    assert_login_failed(&other.get(callback.as_str()).await);

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

    assert_login_failed(&browser.get(callback.as_str()).await);
}

/// Asserts `response` is a failed sign-in: a redirect to the app with an error marker.
fn assert_login_failed(response: &reqwest::Response) {
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let target = location(response);
    assert_eq!(target.path(), "/");
    assert_eq!(query_param(&target, "login_error").as_deref(), Some("1"));
    assert_no_store(response, "a failed sign-in");
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
async fn given_a_session_when_logging_out_then_it_ends_here_and_at_keycloak_without_the_browser() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let sid = browser.cookie("__Host-bff").unwrap().to_owned();
    let keycloak_sid = keycloak_sid(&sid).await;
    assert!(index_members(&keycloak_sid).await.contains(&hash_key(&sid)));
    let session = read_session(&sid).await.unwrap();
    let refresh_token = session["refresh_token"].as_str().unwrap().to_owned();
    let user_id = session["sub"].as_str().unwrap().to_owned();

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
    assert_eq!(
        body["logoutUrl"],
        bff("/").as_str(),
        "Keycloak was told server-side: the SPA just goes to its start page"
    );
    assert!(
        !body.to_string().contains("id_token_hint"),
        "no token for the browser to carry"
    );
    assert!(
        !keycloak_user_session_ids(&user_id)
            .await
            .contains(&keycloak_sid),
        "the Keycloak session is gone"
    );

    assert!(raw_session(&sid).await.is_none(), "session key is deleted");
    assert!(
        !index_members(&keycloak_sid).await.contains(&hash_key(&sid)),
        "the session leaves the back-channel index"
    );
    assert_eq!(
        keycloak_refresh_status(&refresh_token).await,
        StatusCode::BAD_REQUEST,
        "ending the Keycloak session invalidated the refresh token"
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

#[tokio::test]
async fn given_a_session_older_than_the_24_hour_cap_then_it_ends_even_when_active() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let sid = browser.cookie("__Host-bff").unwrap().to_owned();
    let mut session = read_session(&sid).await.unwrap();
    session["created_at"] = (now() - 24 * 3_600 - 1).into();
    write_session(&sid, &session).await;

    let response = browser.get(bff("/auth/session").as_str()).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        raw_session(&sid).await.is_none(),
        "the expired session is deleted"
    );
}

#[tokio::test]
async fn given_a_sign_in_then_the_session_lasts_as_long_as_keycloaks() {
    wait_for_bff().await;
    let idle = keycloak_session_idle_secs().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let sid = browser.cookie("__Host-bff").unwrap().to_owned();

    let ttl = session_ttl(&sid).await;
    assert!(
        (idle as i64 - 30..=idle as i64).contains(&ttl),
        "the session ends with Keycloak's ({idle} s idle): ttl {ttl}"
    );
}

#[tokio::test]
async fn given_a_request_without_a_refresh_then_the_session_is_not_extended() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let sid = browser.cookie("__Host-bff").unwrap().to_owned();
    let mut redis = redis().await;
    let _: () = redis
        .expire(format!("bff:session:{}", hash_key(&sid)), 100)
        .await
        .unwrap();

    let response = browser.get(bff("/auth/session").as_str()).await;

    assert_eq!(response.status(), StatusCode::OK);
    let ttl = session_ttl(&sid).await;
    assert!(
        ttl <= 100,
        "only a refresh extends Keycloak's session, so only a refresh extends this one: ttl {ttl}"
    );
}

#[tokio::test]
async fn given_a_token_refresh_then_the_session_is_extended_with_keycloaks() {
    wait_for_bff().await;
    let idle = keycloak_session_idle_secs().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let sid = browser.cookie("__Host-bff").unwrap().to_owned();
    let mut session = read_session(&sid).await.unwrap();
    session["expires_at"] = 0.into();
    write_session(&sid, &session).await;
    let mut redis = redis().await;
    let _: () = redis
        .expire(format!("bff:session:{}", hash_key(&sid)), 100)
        .await
        .unwrap();

    let response = browser
        .request(Method::GET, bff("/api/echo/whoami").as_str(), &[], None)
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let ttl = session_ttl(&sid).await;
    assert!(
        ttl > idle as i64 - 30,
        "the refresh extended it to Keycloak's {idle} s: ttl {ttl}"
    );
}

#[tokio::test]
async fn given_dot_segments_in_an_api_path_then_they_are_refused() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let cookie = format!("__Host-bff={}", browser.cookie("__Host-bff").unwrap());

    for path in [
        "/api/../echo/x",
        "/api/%2e%2e/echo/x",
        "/api/echo/%2E%2E/%2e%2e/x",
        "/api/..%5Cecho",
    ] {
        assert_eq!(raw_get_status(path, &cookie).await, 400, "{path}");
    }
    assert_eq!(raw_get_status("/api/echo/x", &cookie).await, 200);
}

#[tokio::test]
async fn given_keycloak_fails_during_a_refresh_then_the_session_survives_and_recovers() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let sid = browser.cookie("__Host-bff").unwrap().to_owned();
    let mut session = read_session(&sid).await.unwrap();
    let refresh_token = session["refresh_token"].as_str().unwrap().to_owned();
    session["expires_at"] = 0.into();
    write_session(&sid, &session).await;
    arm_keycloak_fault(&refresh_token, 503).await;

    let failed = browser
        .request(Method::GET, bff("/api/echo/whoami").as_str(), &[], None)
        .await;

    assert_eq!(
        failed.status(),
        StatusCode::BAD_GATEWAY,
        "Keycloak failed, not the BFF"
    );
    let kept = read_session(&sid).await.expect("the session is kept");
    assert_eq!(kept["refresh_token"], refresh_token.as_str());

    let recovered = browser
        .request(Method::GET, bff("/api/echo/whoami").as_str(), &[], None)
        .await;
    assert_eq!(
        recovered.status(),
        StatusCode::OK,
        "the next request refreshes"
    );
}

#[tokio::test]
async fn given_a_logout_token_when_it_is_replayed_then_it_is_refused() {
    wait_for_bff().await;
    // Route Keycloak's back-channel logouts through the recorder, which passes them on to the
    // BFF, so this test can see the real token. Other tests' logouts keep working meanwhile.
    let previous =
        set_backchannel_logout_url("http://echo-api:8000/relay/backchannel-logout").await;
    let captured = tokio::spawn(async {
        let mut browser = Browser::new();
        sign_in(&mut browser, "/").await;
        let sid = browser.cookie("__Host-bff").unwrap().to_owned();
        let keycloak_sid = keycloak_sid(&sid).await;
        end_keycloak_session(&keycloak_sid).await;
        eventually("the first delivery ended the session", || async {
            raw_session(&sid).await.is_none()
        })
        .await;
        recorded_logout_tokens()
            .await
            .into_iter()
            .find(|token| unverified_payload(token)["sid"] == keycloak_sid.as_str())
            .expect("the recorder saw this session's logout token")
    })
    .await;
    // Restore before anything can fail, so a broken run does not leave Keycloak re-pointed.
    set_backchannel_logout_url(&previous).await;
    let logout_token =
        captured.unwrap_or_else(|panic| std::panic::resume_unwind(panic.into_panic()));

    let replayed = reqwest::Client::new()
        .post(bff("/auth/backchannel-logout"))
        .form(&[("logout_token", logout_token.as_str())])
        .send()
        .await
        .unwrap();

    assert!(
        replayed.status().is_client_error(),
        "a logout token is accepted once: {}",
        replayed.status()
    );
}

#[tokio::test]
async fn given_two_sign_ins_started_in_one_browser_then_both_complete() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    let first = sign_in_until_callback(&mut browser, "/first").await;
    let second = sign_in_until_callback(&mut browser, "/second").await;

    let finished_first = browser.get(first.as_str()).await;
    assert_eq!(finished_first.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&finished_first).path(), "/first");

    let finished_second = browser.get(second.as_str()).await;
    assert_eq!(finished_second.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&finished_second).path(), "/second");
}

#[tokio::test]
async fn given_any_request_then_it_carries_a_request_id_through_to_the_api() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    let health = browser.get(bff("/health").as_str()).await;
    assert!(health.headers().get("x-request-id").is_some());

    sign_in(&mut browser, "/").await;
    let response = browser
        .request(
            Method::GET,
            bff("/api/echo/orders").as_str(),
            &[("x-request-id", "trace-from-cloudflare-123")],
            None,
        )
        .await;
    assert_eq!(
        response.headers()["x-request-id"],
        "trace-from-cloudflare-123"
    );
    let echoed: Value = response.json().await.unwrap();
    assert_eq!(
        echoed["headers"]["x-request-id"],
        "trace-from-cloudflare-123"
    );

    let replaced = browser
        .request(
            Method::GET,
            bff("/auth/session").as_str(),
            &[("x-request-id", "not an id")],
            None,
        )
        .await;
    let id = replaced.headers()["x-request-id"].to_str().unwrap();
    assert_ne!(id, "not an id", "text that is not an id is replaced");
}

#[tokio::test]
async fn given_keycloak_fails_during_logout_then_the_browser_gets_keycloaks_logout_page_without_a_token()
 {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let sid = browser.cookie("__Host-bff").unwrap().to_owned();
    let refresh_token = read_session(&sid).await.unwrap()["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    arm_keycloak_fault(&refresh_token, 503).await;

    let response = browser
        .post(bff("/auth/logout").as_str(), &[("x-bff-csrf", "1")])
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    let logout_url = reqwest::Url::parse(body["logoutUrl"].as_str().unwrap()).unwrap();
    assert!(
        logout_url
            .path()
            .ends_with("/protocol/openid-connect/logout"),
        "the user finishes logging out at Keycloak: {logout_url}"
    );
    assert_eq!(
        query_param(&logout_url, "client_id").as_deref(),
        Some("bff")
    );
    assert!(
        query_param(&logout_url, "id_token_hint").is_none(),
        "no token in the URL"
    );
    assert!(
        raw_session(&sid).await.is_none(),
        "the BFF session ended anyway"
    );
}

#[tokio::test]
async fn given_single_use_refresh_tokens_then_each_refresh_keeps_the_rotated_token() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let sid = browser.cookie("__Host-bff").unwrap().to_owned();
    let mut used = Vec::new();

    for _ in 0..2 {
        // Keycloak dates tokens and sessions in whole seconds and only spots a used token that
        // is older than the session's last refresh, so the steps must be a second apart.
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        let mut session = read_session(&sid).await.unwrap();
        used.push(session["refresh_token"].as_str().unwrap().to_owned());
        session["expires_at"] = 0.into();
        write_session(&sid, &session).await;

        let response = browser
            .request(Method::GET, bff("/api/echo/whoami").as_str(), &[], None)
            .await;
        assert_eq!(response.status(), StatusCode::OK, "the refresh worked");
    }

    let current = read_session(&sid).await.unwrap()["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        !used.contains(&current),
        "every refresh stored a new refresh token"
    );
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    for old in &used {
        assert_eq!(
            keycloak_refresh_status(old).await,
            StatusCode::BAD_REQUEST,
            "a used refresh token is refused"
        );
    }
}

#[tokio::test]
async fn given_parallel_requests_with_an_expired_token_then_one_refresh_serves_them_all() {
    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let sid = browser.cookie("__Host-bff").unwrap().to_owned();
    let mut session = read_session(&sid).await.unwrap();
    let before = session["refresh_token"].as_str().unwrap().to_owned();
    session["expires_at"] = 0.into();
    write_session(&sid, &session).await;

    // With single-use refresh tokens, two refreshes of the same token would end the session.
    let mut calls = tokio::task::JoinSet::new();
    for _ in 0..5 {
        let request = reqwest::Client::new()
            .get(bff("/api/echo/whoami"))
            .header("cookie", format!("__Host-bff={sid}"))
            .header("cf-connecting-ip", browser.client_ip.as_str());
        calls.spawn(async move { request.send().await.unwrap().status() });
    }
    let statuses = calls.join_all().await;

    assert!(
        statuses.iter().all(|status| *status == StatusCode::OK),
        "{statuses:?}"
    );
    let after = read_session(&sid).await.expect("the session survived");
    assert_ne!(after["refresh_token"], before.as_str(), "it was refreshed");
}

#[tokio::test]
async fn given_a_bff_that_trusts_no_proxy_then_a_forged_client_ip_header_is_ignored() {
    wait_for_bff().await;
    // Every request claims a different address. If the header were believed, each would get
    // its own allowance; ignored, they all count against this machine's one address.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let mut statuses = Vec::new();
    for attempt in 0..11 {
        let response = client
            .get(untrusted_bff("/auth/login?returnUrl=/"))
            .header("cf-connecting-ip", format!("198.51.100.{attempt}"))
            .send()
            .await
            .expect("the untrusting BFF is running; is docker-compose.test.yml in use?");
        statuses.push(response.status());
    }

    assert!(
        statuses.contains(&StatusCode::TOO_MANY_REQUESTS),
        "11 sign-ins from one real address hit the limit of 10: {statuses:?}"
    );
}

/// Hands verified payloads back untouched.
struct RawPayload;

impl oidc::ProviderClaims for RawPayload {
    type Claims = Value;
    fn claims(payload: Value) -> Result<Value, oidc::oidc::JwtVerificationError> {
        Ok(payload)
    }
}

#[tokio::test]
async fn given_a_signed_in_user_then_the_api_accepts_the_access_token_the_bff_forwards() {
    use oidc::oidc::JwtVerifier;

    wait_for_bff().await;
    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let sid = browser.cookie("__Host-bff").unwrap().to_owned();

    let response = browser
        .request(Method::GET, bff("/api/echo/whoami").as_str(), &[], None)
        .await;
    let echoed: Value = response.json().await.unwrap();
    let forwarded = echoed["headers"]["authorization"]
        .as_str()
        .and_then(|value| value.strip_prefix("Bearer "))
        .expect("the API received a bearer token")
        .to_owned();

    // Verified exactly as the API verifies: Keycloak's keys, its issuer, the API's audience.
    let api_verifier = oidc::OidcJwtVerifier::<RawPayload>::new(
        "http://localhost:8080/realms/test",
        reqwest::Client::new(),
        "authentication.layer.api".to_owned(),
        oidc::Transport::AllowInsecureHttp,
    )
    .await
    .expect("the dev Keycloak is reachable");
    let claims = api_verifier
        .verify(&forwarded)
        .await
        .expect("the API's audience is in the BFF's access tokens");
    assert_eq!(
        claims["typ"], "Bearer",
        "an access token, as the API requires"
    );
    assert_eq!(claims["azp"], "bff");
    // Only openid is requested and the client's default scopes are basic, roles and acr: no
    // personal data and no CORS origins ride along to the API.
    for absent in [
        "email",
        "name",
        "preferred_username",
        "given_name",
        "family_name",
        "allowed-origins",
    ] {
        assert!(
            claims.get(absent).is_none(),
            "{absent} is not in the access token"
        );
    }
    // Full scope is off: only the API's audience and the roles mapped to the client.
    assert_eq!(
        claims["aud"], "authentication.layer.api",
        "no other audiences"
    );
    assert!(claims.get("resource_access").is_none(), "no client roles");
    // alice's default roles stay out; the admin-role test may grant her the one mapped role
    // while this test signs in.
    let roles = claims["realm_access"]["roles"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        roles.iter().all(|role| role == "multi-tenancy-admin"),
        "only roles mapped to the client: {roles:?}"
    );

    let id_token = read_session(&sid).await.unwrap()["id_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        unverified_payload(&id_token)["aud"],
        "bff",
        "ID tokens stay addressed to the BFF alone"
    );
}

#[tokio::test]
async fn given_a_user_with_the_apis_admin_role_then_only_that_role_reaches_the_api() {
    wait_for_bff().await;
    // Granted to alice only for this sign-in. Other tests signing in meanwhile may get it too;
    // the only one that looks at roles allows for that.
    set_realm_role(USERNAME, "multi-tenancy-admin", true).await;
    let signed_in = tokio::spawn(async {
        let mut browser = Browser::new();
        sign_in(&mut browser, "/").await;
        browser.cookie("__Host-bff").unwrap().to_owned()
    })
    .await;
    set_realm_role(USERNAME, "multi-tenancy-admin", false).await;
    let sid = signed_in.unwrap_or_else(|panic| std::panic::resume_unwind(panic.into_panic()));

    let access_token = read_session(&sid).await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let claims = unverified_payload(&access_token);
    assert_eq!(
        claims["realm_access"]["roles"],
        serde_json::json!(["multi-tenancy-admin"]),
        "the mapped role, and none of alice's default roles"
    );
}

#[tokio::test]
async fn given_the_metrics_page_then_it_is_served_only_on_its_own_address() {
    wait_for_bff().await;
    let public = reqwest::get(bff("/metrics")).await.unwrap();
    assert_eq!(
        public.status(),
        StatusCode::NOT_FOUND,
        "not on the public port"
    );

    let page = metrics_page().await;
    assert!(
        page.contains("# TYPE bff_http_requests_total counter"),
        "{page}"
    );
    assert!(page.contains("# TYPE bff_http_request_duration_seconds histogram"));
}

#[tokio::test]
async fn given_sign_ins_api_calls_and_refreshes_then_they_are_counted() {
    wait_for_bff().await;
    let sign_ins = r#"bff_sign_ins_total{outcome="completed"}"#;
    let refreshes = r#"bff_token_refreshes_total{outcome="refreshed"}"#;
    let api_calls = r#"bff_http_requests_total{route="/api/{*rest}",method="GET",status="200"}"#;
    let before = metrics_page().await;

    let mut browser = Browser::new();
    sign_in(&mut browser, "/").await;
    let sid = browser.cookie("__Host-bff").unwrap().to_owned();
    let mut session = read_session(&sid).await.unwrap();
    session["expires_at"] = 0.into();
    write_session(&sid, &session).await;
    let response = browser
        .request(Method::GET, bff("/api/echo/whoami").as_str(), &[], None)
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Other tests run at the same time, so the counts grow by at least this test's share.
    let after = metrics_page().await;
    for series in [sign_ins, refreshes, api_calls] {
        assert!(
            metric(&after, series) >= metric(&before, series) + 1.0,
            "{series} counted"
        );
    }
    assert!(
        after.contains(
            r#"bff_http_request_duration_seconds_bucket{route="/api/{*rest}",method="GET",le="+Inf"}"#
        ),
        "API calls are timed"
    );
}

#[tokio::test]
async fn given_a_sign_in_asking_for_other_scopes_then_the_bff_requests_only_its_own() {
    wait_for_bff().await;
    let mut browser = Browser::new();

    let response = browser
        .get(&format!(
            "{}&scope=openid%20offline_access%20email",
            login_url("/")
        ))
        .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        query_param(&location(&response), "scope").as_deref(),
        Some("openid"),
        "the browser has no say in the scopes"
    );
}

#[tokio::test]
async fn given_private_key_jwt_then_the_bff_publishes_only_its_public_key() {
    wait_for_bff().await;
    let jwks: Value = reqwest::get(bff("/.well-known/jwks.json"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let key = &jwks["keys"][0];
    assert_eq!(key["kty"], "EC");
    assert_eq!(key["alg"], "ES256");
    assert!(key["kid"].as_str().is_some_and(|kid| !kid.is_empty()));
    assert!(key.get("d").is_none(), "no private key material");
}

#[tokio::test]
async fn given_private_key_jwt_then_the_old_client_secret_no_longer_authenticates_the_bff() {
    wait_for_bff().await;
    let (status, error) = token_request(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", "irrelevant"),
        ("client_id", "bff"),
        ("client_secret", "bff.secret"),
    ])
    .await;

    // invalid_client, as 400: OAuth only requires 401 for the Authorization header.
    assert!(status.is_client_error());
    assert_eq!(error.as_deref(), Some("invalid_client"));
}

#[tokio::test]
async fn given_a_client_assertion_then_keycloak_accepts_it_once_and_never_after_it_expires() {
    wait_for_bff().await;
    let kid = bff_client_key_id().await;
    let request = |assertion: String| async move {
        token_request(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "not-a-refresh-token"),
            ("client_id", "bff"),
            ("client_assertion_type", JWT_BEARER),
            ("client_assertion", &assertion),
        ])
        .await
    };
    let assertion = client_assertion(&dev_client_key(), &kid, 60);

    // Accepted as the client: the failure is the made-up refresh token, not the assertion.
    let (_, first) = request(assertion.clone()).await;
    assert_eq!(
        first.as_deref(),
        Some("invalid_grant"),
        "the client is authenticated"
    );

    // Keycloak answers invalid_client with 400 here: OAuth only requires 401 when the client
    // authenticated with the Authorization header.
    let (_, replayed) = request(assertion).await;
    assert_eq!(
        replayed.as_deref(),
        Some("invalid_client"),
        "an assertion works once"
    );

    let (_, expired) = request(client_assertion(&dev_client_key(), &kid, -120)).await;
    assert_eq!(
        expired.as_deref(),
        Some("invalid_client"),
        "an expired assertion is refused"
    );
}

#[tokio::test]
async fn given_a_client_assertion_signed_with_another_key_then_keycloak_refuses_it() {
    wait_for_bff().await;
    let kid = bff_client_key_id().await;
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &ring::rand::SystemRandom::new(),
    )
    .unwrap();
    let forged_key = jsonwebtoken::EncodingKey::from_ec_der(pkcs8.as_ref());

    let (_, error) = token_request(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", "not-a-refresh-token"),
        ("client_id", "bff"),
        ("client_assertion_type", JWT_BEARER),
        ("client_assertion", &client_assertion(&forged_key, &kid, 60)),
    ])
    .await;

    assert_eq!(error.as_deref(), Some("invalid_client"));
}
