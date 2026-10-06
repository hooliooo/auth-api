use axum::Form;
use axum::Json;
use axum::http::header::REFERRER_POLICY;
use axum::http::header::SET_COOKIE;
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
use serde_json::Map;
use serde_json::Value;
use thiserror::Error;
use tracing::info;
use tracing::warn;

use crate::sealed;
use crate::sealed::Purpose;
use crate::session::CurrentSession;
use crate::{
    cookie,
    crypto::{constant_time_eq, hash_key},
    error::AppError,
    pkce::{CodeVerifier, PkceError, S256},
    random::{RandomUnvailable, random_token},
    session::{self, SSO_IDLE_SECS, Session, now},
    state::AppState,
};

const LOGIN_TTL_SECS: u64 = 300;
const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

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
    Query(q): Query<LoginQuery>,
) -> Result<Response, AppError> {
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
    match id_token_claims.nonce.as_deref() {
        Some(nonce) if constant_time_eq(nonce, &pending_login.nonce) => {}
        _ => return Err(LoginError::InvalidNonce.into()),
    }

    // Session management
    if let Some(old) = cookie::get(&headers, cookie::SESSION) {
        session::delete(&mut redis, &old).await?;
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
        cookie::set(cookie::SESSION, &sid, "Strict", SSO_IDLE_SECS)?,
    );
    headers.append(SET_COOKIE, cookie::clear(cookie::LOGIN, "Lax")?);
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    Ok(response)
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
    session::delete(&mut redis, &current_session.id).await?;

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
    Ok(response)
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

#[derive(Deserialize)]
struct LogoutTokenClaims {
    sid: Option<String>,
    nonce: Option<Value>,
    events: Map<String, Value>,
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

    let claims: LogoutTokenClaims = serde_json::from_value(json)?;
    if !claims.events.contains_key(BACKCHANNEL_LOGOUT_EVENT) || claims.nonce.is_some() {
        return Err(LoginError::InvalidBackchannelLogoutToken.into());
    }
    let iam_sid = claims.sid.ok_or(LoginError::MissingSid)?;
    let mut redis = app_state.redis.clone();
    let removed = session::delete_by_iam_sid(&mut redis, &iam_sid).await?;
    info!(removed, "backchannel logout ended sessions");
    Ok(StatusCode::OK)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionInfo {
    sub: String,
}

async fn current(current: CurrentSession) -> Json<SessionInfo> {
    let s = current.session;
    Json(SessionInfo { sub: s.sub })
}
