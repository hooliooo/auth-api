use std::{collections::HashSet, sync::Arc};

use auth_core::domain::authorization::authorized_scope::AuthorizedScope;
use axum::{Json, extract::FromRequestParts, http::request::Parts, response::IntoResponse};
use axum_extra::headers::{Authorization, HeaderMapExt, authorization::Bearer};
use jsonwebtoken::{
    DecodingKey, TokenData, Validation, decode, decode_header, errors::ErrorKind, jwk::JwkSet,
};
use kern::{application::role::Role, infrastructure::error::axum_extensions::StatusCodeError};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::Value;

#[derive(Clone, Debug, Deserialize)]
pub struct WellKnownEndpoint {
    pub issuer: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

#[async_trait::async_trait]
pub trait JwtVerifier: Send + Sync {
    fn jwks_uri(&self) -> &str;

    async fn verify(
        &self,
        raw_token: &str,
    ) -> Result<Box<dyn ClaimsExtractor>, JwtVerificationError>;
}

pub trait JwtVerifierState {
    fn jwt_verifier(&self) -> Arc<dyn JwtVerifier>;
}

pub trait ClaimsExtractor {
    fn extract(self: Box<Self>) -> Claims;
}

#[derive(Clone, Debug)]
pub struct KeycloakJwtVerifier {
    well_known_endpoint: WellKnownEndpoint,
    client: reqwest::Client,
    audience: String,
    validate_expiration: bool,
}

impl KeycloakJwtVerifier {
    pub async fn new(
        url: String,
        client: reqwest::Client,
        audience: String,
        validate_expiration: bool,
    ) -> Self {
        let well_known_endpoint = client
            .get(url)
            .send()
            .await
            .unwrap()
            .json::<WellKnownEndpoint>()
            .await
            .unwrap();
        Self {
            well_known_endpoint,
            client,
            audience,
            validate_expiration,
        }
    }

    pub fn token_endpoint(&self) -> &str {
        &self.well_known_endpoint.token_endpoint
    }
}

#[async_trait::async_trait]
impl JwtVerifier for KeycloakJwtVerifier {
    fn jwks_uri(&self) -> &str {
        &self.well_known_endpoint.jwks_uri
    }

    async fn verify(
        &self,
        raw_token: &str,
    ) -> Result<Box<dyn ClaimsExtractor>, JwtVerificationError> {
        let Ok(header) = decode_header(raw_token) else {
            return Err(JwtVerificationError::InvalidJwt);
        };

        let Ok(certs_request) = self.client.get(self.jwks_uri()).send().await else {
            return Err(JwtVerificationError::CertsUrlInvalid);
        };

        let jwk_set: JwkSet = certs_request.json().await.unwrap();
        let Some(jwk) = jwk_set.find(&header.kid.unwrap()) else {
            return Err(JwtVerificationError::JwkNotFound);
        };

        let decoding_key = DecodingKey::from_jwk(jwk).unwrap();

        let validation = {
            let mut validation = Validation::new(header.alg);
            validation.set_audience(&[self.audience.as_str()]);
            validation.set_issuer(&[self.well_known_endpoint.issuer.as_str()]);
            validation.validate_exp = self.validate_expiration;
            validation
        };

        let token = match decode::<serde_json::Value>(raw_token, &decoding_key, &validation) {
            Ok(token) => token,
            Err(error) => return Err(JwtVerificationError::ValidationError(error.into_kind())),
        };
        Ok(Box::new(JWT(token)))
    }
}

#[derive(Clone, Debug)]
pub struct JWT(TokenData<Value>);

impl ClaimsExtractor for JWT {
    fn extract(self: Box<Self>) -> Claims {
        let claims: Value = self.0.claims;
        let client_id: &str = claims.get("client_id").unwrap().as_str().unwrap();
        let user_id: &str = claims.get("sub").unwrap().as_str().unwrap();
        let realm_roles: HashSet<Role> = claims
            .pointer("/realm_access/roles")
            .and_then(|roles| roles.as_array())
            .map(|roles| {
                roles
                    .iter()
                    .filter_map(|value| value.as_str())
                    .map(|str| Role::new(str.to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        let authorized_scope = if realm_roles.contains("realm-admin") {
            AuthorizedScope::RealmAdmin
        } else {
            AuthorizedScope::User
        };

        Claims {
            client_id: client_id.to_owned(),
            user_id: user_id.to_owned(),
            authorized_scope,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Claims {
    pub client_id: String,
    pub user_id: String,
    pub authorized_scope: AuthorizedScope,
}

pub enum JwtHeaderError {
    MissingAuthorizationHeader,
    MissingBearerToken,
    InvalidJwt(JwtVerificationError),
}

impl IntoResponse for JwtHeaderError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::MissingAuthorizationHeader => {
                (StatusCode::UNAUTHORIZED, "Authorization required").into_response()
            }
            Self::MissingBearerToken => {
                (StatusCode::UNAUTHORIZED, "Bearer token required").into_response()
            }
            Self::InvalidJwt(verification_error) => (
                StatusCode::UNAUTHORIZED,
                format!("Invalid Jwt: {:?}", verification_error),
            )
                .into_response(),
        }
    }
}

impl<S> FromRequestParts<S> for Claims
where
    S: JwtVerifierState,
    S: Send + Sync,
{
    #[doc = " If the extractor fails it\'ll use this \"rejection\" type. A rejection is"]
    #[doc = " a kind of error that can be converted into a response."]
    type Rejection = JwtHeaderError;

    #[doc = " Perform the extraction."]
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let header = parts.headers.typed_get::<Authorization<Bearer>>();
        let token = match header {
            Some(Authorization(bearer)) => bearer.token().to_string(),
            None => return Err(JwtHeaderError::MissingBearerToken),
        };

        let jwt = match state.jwt_verifier().verify(&token).await {
            Ok(token) => token,
            Err(error) => return Err(JwtHeaderError::InvalidJwt(error)),
        };
        dbg!("Extracting JWT claims");
        Ok(jwt.extract())
    }
}

#[derive(Debug)]
pub enum JwtVerificationError {
    InvalidJwt,
    CertsUrlInvalid,
    JwkNotFound,
    ValidationError(ErrorKind),
}

impl std::fmt::Display for JwtVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJwt => write!(f, "InvalidJwt"),
            Self::CertsUrlInvalid => write!(f, "Certs URL Invalid"),
            Self::JwkNotFound => write!(f, "Jwk Not Found"),
            Self::ValidationError(error_kind) => write!(f, "Validation Error: {:?}", error_kind),
        }
    }
}

impl std::error::Error for JwtVerificationError {}

impl IntoResponse for JwtVerificationError {
    fn into_response(self) -> axum::response::Response {
        let message = match self {
            JwtVerificationError::InvalidJwt => "Invalid JWT".to_string(),
            JwtVerificationError::CertsUrlInvalid => "Invalid Certs".to_string(),
            JwtVerificationError::JwkNotFound => "Jwk Not Found".to_string(),
            JwtVerificationError::ValidationError(error_kind) => {
                format!("{:?}", error_kind).to_lowercase()
            }
        };

        (
            StatusCode::BAD_REQUEST,
            Json(StatusCodeError::new(
                "error.jwt.invalid".to_string(),
                message,
            )),
        )
            .into_response()
    }
}
