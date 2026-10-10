use axum::Form;
use axum::Json;
use axum::http::header::REFERRER_POLICY;
use axum::http::header::{CACHE_CONTROL, SET_COOKIE};
use axum::routing::post;
use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use oidc::oidc::{JwtVerificationError, JwtVerifier};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tracing::info;
use tracing::warn;

#[cfg(feature = "rate-limit")]
use std::net::SocketAddr;

#[cfg(feature = "rate-limit")]
use axum::extract::ConnectInfo;

use crate::sealed;
use crate::sealed::Purpose;
use crate::session::CurrentSession;
#[cfg(feature = "rate-limit")]
use crate::{client_ip::client_ip, rate_limit};
use crate::{
    cookie,
    crypto::{constant_time_eq, hash_key},
    error::AppError,
    pkce::{CodeVerifier, PkceError, S256},
    random::{RandomUnvailable, random_token},
    session::{self, SSO_MAX_SECS, Session, now},
    state::AppState,
};

const LOGIN_TTL_SECS: u64 = 300;
/// How old a back-channel logout token may be; older ones are refused even before they expire.
const LOGOUT_TOKEN_MAX_AGE_SECS: u64 = 120;
/// How long a logout token's `jti` is remembered: past this, its `iat` is too old anyway.
const LOGOUT_JTI_TTL_SECS: u64 = LOGOUT_TOKEN_MAX_AGE_SECS + 2 * oidc::oidc::LEEWAY_SECS;
/// Keycloak's `typ` for ID tokens.
const ID_TOKEN_TYPE: &str = "ID";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", post(logout))
        .route("/auth/backchannel-logout", post(backchannel_logout))
        .route("/auth/session", get(current))
}

#[derive(Debug, Error)]
pub enum LoginError {
    #[error("Code exchange error: '{0}'")]
    CodeExchangeError(String),
    #[error("Cookie error: '{0}'")]
    CookieError(String),
    #[error("Invalid authorization_endpoint: '{0}'")]
    InvalidAuthorizationEndpoint(String),
    #[error("Invalid backchannel logout token")]
    InvalidBackchannelLogoutToken,
    #[error("Invalid ID token: {0}")]
    InvalidIdToken(&'static str),
    #[error("Missing code or state")]
    InvalidCallbackQuery,
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("Pending login expired or already used")]
    InvalidPendingLogin,
    #[error("Invalid redirect_uri: '{0}'")]
    InvalidRedirectUri(String),
    #[error("state mismatch with state from cookie")]
    InvalidStateParam,
    #[error(transparent)]
    JwtVerificationError(JwtVerificationError),
    #[error("Missing sid")]
    MissingSid,
    #[error("PkceError: {0}")]
    PkceError(PkceError),
    #[error("Could not generate random values")]
    RandomError(RandomUnvailable),
    #[error("IAM rejected sign-in")]
    SignIn,
}

impl From<RandomUnvailable> for LoginError {
    fn from(value: RandomUnvailable) -> Self {
        Self::RandomError(value)
    }
}

impl From<PkceError> for LoginError {
    fn from(value: PkceError) -> Self {
        Self::PkceError(value)
    }
}

#[derive(Debug, Deserialize)]
struct LoginQuery {
    #[serde(rename = "returnUrl")]
    pub return_url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PendingLogin {
    pub verifier: CodeVerifier,
    pub nonce: String,
    pub return_to: String,
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    id_token: String,
    refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: String,
    nonce: Option<String>,
    typ: Option<String>,
    azp: Option<String>,
    /// A single string or a list (OIDC Core §2).
    aud: Value,
    #[serde(rename = "sid")]
    iam_sid: Option<String>,
    // preferred_username: Option<String>,
    // name: Option<String>,
    // email: Option<String>,
}

fn sanitize_return_url(url: Option<&str>, base: &Url) -> String {
    let Some(u) = url else { return "/".into() };
    match base.join(u) {
        Ok(resolved) if resolved.origin() == base.origin() => {
            let mut out = resolved.path().to_string();
            if let Some(q) = resolved.query() {
                out.push('?');
                out.push_str(q);
            }
            if let Some(f) = resolved.fragment() {
                out.push('#');
                out.push_str(f);
            }

            out
        }
        _ => "/".into(),
    }
}

fn login_key(state: &str) -> String {
    format!("bff:login:{}", hash_key(state))
}

async fn login(
    State(s): State<AppState>,
    #[cfg(feature = "rate-limit")] ConnectInfo(peer): ConnectInfo<SocketAddr>,
    #[cfg(feature = "rate-limit")] request_headers: HeaderMap,
    Query(q): Query<LoginQuery>,
) -> Result<Response, AppError> {
    // Every sign-in start writes to Redis without a session, so it is limited per client.
    #[cfg(feature = "rate-limit")]
    {
        let client = client_ip(&request_headers, peer, s.client_ip_header.as_ref());
        rate_limit::check_login(&mut s.redis.clone(), client, s.login_per_minute).await?;
    }

    let (state, nonce, verifier) = (
        random_token()?,
        random_token()?,
        CodeVerifier::new_random()?,
    );

    let challenge = verifier.to_challenge::<S256>();
    let redirect_uri = s.redirect_uri();
    let base_url = Url::parse(redirect_uri)
        .and_then(|u| u.join("/"))
        .map_err(|_| LoginError::InvalidRedirectUri(redirect_uri.to_owned()))?;

    let pending = PendingLogin {
        verifier,
        nonce: nonce.clone(),
        return_to: sanitize_return_url(q.return_url.as_deref(), &base_url),
    };

    let sealed_pending = sealed::seal(
        &state,
        Purpose::PendingLogin,
        &serde_json::to_vec(&pending)?,
    )?;

    let mut redis = s.redis.clone();
    redis::cmd("SET")
        .arg(login_key(&state))
        .arg(sealed_pending)
        .arg("EX")
        .arg(LOGIN_TTL_SECS)
        .query_async::<()>(&mut redis)
        .await?;

    let authz_endpoint = s.authorization_endpoint();
    let mut url = Url::parse(authz_endpoint)
        .map_err(|_| LoginError::InvalidAuthorizationEndpoint(authz_endpoint.to_owned()))?;

    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", s.client_id())
        .append_pair("redirect_uri", s.redirect_uri())
        .append_pair("state", &state)
        .append_pair("scope", "openid profile email")
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", challenge.as_str())
        .append_pair("code_challenge_method", challenge.name());
    let mut response = Redirect::to(url.as_str()).into_response();
    response.headers_mut().append(
        SET_COOKIE,
        cookie::set(cookie::LOGIN, &state, "Lax", LOGIN_TTL_SECS)?,
    );
    Ok(response)
}

async fn callback(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, AppError> {
    if let Some(error) = q.error.as_deref() {
        warn!(error, description = ?q.error_description, "IAM rejected sign-in");
        return Err(LoginError::SignIn.into());
    }

    let (code, state) = q
        .code
        .zip(q.state)
        .ok_or(LoginError::InvalidCallbackQuery)?;

    let state_from_cookie = cookie::get(&headers, cookie::LOGIN)
        .ok_or(LoginError::CookieError("missing cookie".to_owned()))?;

    if !constant_time_eq(&state, &state_from_cookie) {
        return Err(LoginError::InvalidStateParam.into());
    }

    let mut redis = s.redis.clone();
    let raw_pending_login: Option<Vec<u8>> = redis::cmd("GETDEL")
        .arg(login_key(&state))
        .query_async(&mut redis)
        .await?;
    let plaintext = raw_pending_login
        .and_then(|raw| sealed::open(&state, Purpose::PendingLogin, &raw))
        .ok_or(LoginError::InvalidPendingLogin)?;
    let pending_login: PendingLogin = serde_json::from_slice(&plaintext)?;

    let token_response = exchange_code(&s, code.as_str(), &pending_login.verifier).await?;
    let json = s
        .oidc
        .verifier
        .verify(&token_response.id_token)
        .await
        .map_err(LoginError::JwtVerificationError)?;
    let id_token_claims = serde_json::from_value::<IdTokenClaims>(json)?;
    check_id_token(&id_token_claims, s.client_id())?;
    match id_token_claims.nonce.as_deref() {
        Some(nonce) if constant_time_eq(nonce, &pending_login.nonce) => {}
        _ => return Err(LoginError::InvalidNonce.into()),
    }

    // Session management
    if let Some(old) = cookie::get(&headers, cookie::SESSION) {
        let old_iam_sid = session::load(&mut redis, &old).await?.and_then(|s| s.sid);
        session::delete(&mut redis, &old, old_iam_sid.as_deref()).await?;
    }

    let sid = random_token()?;
    let issued_at = now();
    session::save(
        &mut redis,
        &sid,
        &Session {
            sub: id_token_claims.sub,
            sid: id_token_claims.iam_sid,
            id_token: token_response.id_token,
            access_token: token_response.access_token,
            refresh_token: token_response.refresh_token,
            expires_at: issued_at + token_response.expires_in,
            created_at: issued_at,
        },
    )
    .await?;

    let mut response = Redirect::to(&pending_login.return_to).into_response();
    let headers = response.headers_mut();
    headers.append(
        SET_COOKIE,
        cookie::set(cookie::SESSION, &sid, "Strict", SSO_MAX_SECS)?,
    );
    headers.append(SET_COOKIE, cookie::clear(cookie::LOGIN, "Lax")?);
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    Ok(no_store(response))
}

async fn exchange_code(
    app_state: &AppState,
    code: &str,
    verifier: &CodeVerifier,
) -> Result<TokenResponse, AppError> {
    let config = &app_state.oidc.config;
    let response = app_state
        .http
        .post(app_state.oidc.token_endpoint())
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", config.redirect_uri.as_str()),
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .map_err(|err| LoginError::CodeExchangeError(err.to_string()))?;
    if !response.status().is_success() {
        let status = response.status();
        return Err(AppError::LoginError(LoginError::CodeExchangeError(
            format!("Code exchange returned a {status}"),
        )));
    }
    let result = response
        .json::<TokenResponse>()
        .await
        .map_err(|e| LoginError::CodeExchangeError(e.to_string()))?;
    Ok(result)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogoutResponse {
    logout_url: String,
}

async fn logout(
    State(app_state): State<AppState>,
    current_session: CurrentSession,
) -> Result<Response, AppError> {
    let mut redis = app_state.redis.clone();
    session::delete(
        &mut redis,
        &current_session.id,
        current_session.session.sid.as_deref(),
    )
    .await?;

    if let Some(refresh_token) = current_session.session.refresh_token.as_deref() {
        revoke_best_effort(&app_state, refresh_token).await;
    }

    let mut url = app_state.oidc.end_session_url.clone();
    url.query_pairs_mut()
        .append_pair("id_token_hint", &current_session.session.id_token)
        .append_pair(
            "post_logout_redirect_uri",
            app_state.oidc.public_base_url.as_str(),
        )
        .append_pair("client_id", app_state.client_id());

    let mut response = Json(LogoutResponse {
        logout_url: url.to_string(),
    })
    .into_response();
    response
        .headers_mut()
        .append(SET_COOKIE, cookie::clear(cookie::SESSION, "Strict")?);
    Ok(no_store(response))
}

async fn revoke_best_effort(app_state: &AppState, refresh_token: &str) {
    let result = app_state
        .http
        .post(app_state.oidc.revocation_endpoint())
        .form(&[
            ("token", refresh_token),
            ("token_type_hint", "refresh_token"),
            ("client_id", app_state.client_id()),
            ("client_secret", app_state.client_secret()),
        ])
        .send()
        .await;
    match result {
        Ok(r) if r.status().is_success() => {}
        Ok(r) => warn!(status = %r.status(), "refresh token revocation rejected"),
        Err(err) => warn!(%err, "refresh token revocation failed"),
    }
}

#[derive(Deserialize)]
struct LogoutTokenForm {
    logout_token: String,
}

async fn backchannel_logout(
    State(app_state): State<AppState>,
    Form(form): Form<LogoutTokenForm>,
) -> Result<StatusCode, AppError> {
    let json = app_state
        .oidc
        .verifier
        .verify(&form.logout_token)
        .await
        .map_err(LoginError::JwtVerificationError)?;

    // The logout event, no nonce, a session or subject, and a fresh iat (Back-Channel Logout §2.6).
    let claims = oidc::logout::logout_claims(&json, now(), LOGOUT_TOKEN_MAX_AGE_SECS)
        .map_err(LoginError::JwtVerificationError)?;
    let iam_sid = claims.sid.ok_or(LoginError::MissingSid)?;
    let mut redis = app_state.redis.clone();

    // Each logout token is accepted once: a captured token replayed later is refused.
    let first_use: Option<String> = redis::cmd("SET")
        .arg(format!("bff:logout-jti:{}", hash_key(&claims.jti)))
        .arg(1)
        .arg("NX")
        .arg("EX")
        .arg(LOGOUT_JTI_TTL_SECS)
        .query_async(&mut redis)
        .await?;
    if first_use.is_none() {
        return Err(LoginError::InvalidBackchannelLogoutToken.into());
    }

    let removed = session::delete_by_iam_sid(&mut redis, &iam_sid).await?;
    info!(removed, "backchannel logout ended sessions");
    Ok(StatusCode::OK)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionInfo {
    sub: String,
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn current(current: CurrentSession) -> Response {
    let s = current.session;
    no_store(Json(SessionInfo { sub: s.sub }).into_response())
}

/// The ID token checks OIDC Core §3.1.3.7 adds to signature, issuer, audience and expiry:
/// it must be an ID token, and if it names an authorized party, that must be this client.
fn check_id_token(claims: &IdTokenClaims, client_id: &str) -> Result<(), LoginError> {
    if claims.typ.as_deref() != Some(ID_TOKEN_TYPE) {
        return Err(LoginError::InvalidIdToken("not an ID token"));
    }
    let several_audiences = claims
        .aud
        .as_array()
        .is_some_and(|audiences| audiences.len() > 1);
    match claims.azp.as_deref() {
        Some(azp) if azp != client_id => {
            Err(LoginError::InvalidIdToken("issued to another client"))
        }
        None if several_audiences => Err(LoginError::InvalidIdToken("several audiences, no azp")),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn id_token(extra: Value) -> IdTokenClaims {
        let mut claims = json!({ "sub": "user", "typ": "ID", "aud": "bff", "azp": "bff" });
        for (key, value) in extra.as_object().unwrap() {
            if value.is_null() {
                claims.as_object_mut().unwrap().remove(key);
            } else {
                claims[key] = value.clone();
            }
        }
        serde_json::from_value(claims).unwrap()
    }

    #[test]
    fn given_an_id_token_for_this_client_then_it_is_accepted() {
        assert!(check_id_token(&id_token(json!({})), "bff").is_ok());
        assert!(check_id_token(&id_token(json!({ "azp": null })), "bff").is_ok());
    }

    #[test]
    fn given_another_token_type_then_it_is_refused() {
        for typ in [json!("Bearer"), json!("Logout"), Value::Null] {
            assert!(check_id_token(&id_token(json!({ "typ": typ })), "bff").is_err());
        }
    }

    #[test]
    fn given_another_authorized_party_then_it_is_refused() {
        assert!(check_id_token(&id_token(json!({ "azp": "other" })), "bff").is_err());
    }

    #[test]
    fn given_several_audiences_then_azp_is_required() {
        let several = json!({ "aud": ["bff", "account"], "azp": null });
        assert!(check_id_token(&id_token(several), "bff").is_err());
        let with_azp = json!({ "aud": ["bff", "account"] });
        assert!(check_id_token(&id_token(with_azp), "bff").is_ok());
    }
}
