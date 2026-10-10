//! Assembling the application. This is the only module that knows every resource: it builds
//! the dependencies, the shared [`AppState`], and the router with its middleware.

use std::{sync::Arc, time::Duration};

use auth_core::application::{authentication::Claims, authorization::AuthAPIAuthorizationService};
use axum::{
    Router,
    extract::MatchedPath,
    http::{HeaderMap, Request, header},
    response::Response,
};
use jwt::keycloak::KeycloakJwtVerifier;
use kern::infrastructure::event::event_bus::TokioEventBus;
use oidc::oidc::JwtVerifier;
use tower_http::{
    classify::ServerErrorsFailureClass, sensitive_headers::SetSensitiveRequestHeadersLayer,
    trace::TraceLayer,
};
use tracing::{Span, info_span};
use write_model::database_setup;

use crate::{Transport, auth::JwtVerifierState, health, organization};

/// The state every router shares. Dependencies used across resources, like the JWT verifier,
/// live here once; each resource's handlers pull their own slice out with `FromRef`.
#[derive(Clone)]
pub struct AppState {
    jwt_verifier: Arc<dyn JwtVerifier<Claims = Claims>>,
    pub(crate) organization: organization::OrganizationState,
}

impl AppState {
    pub fn new(
        jwt_verifier: Arc<dyn JwtVerifier<Claims = Claims>>,
        organization: organization::OrganizationState,
    ) -> Self {
        Self {
            jwt_verifier,
            organization,
        }
    }
}

impl JwtVerifierState for AppState {
    fn jwt_verifier(&self) -> Arc<dyn JwtVerifier<Claims = Claims>> {
        self.jwt_verifier.clone()
    }
}

/// Builds the dependencies and returns the application, ready to serve.
pub async fn build(
    oauth2_url: &str,
    database_url: &str,
    audience: &str,
    transport: Transport,
) -> Router {
    let state = build_state(oauth2_url, database_url, audience, transport).await;
    router(state)
}

/// Every route, with the middleware that applies to all of them.
pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(health::router())
        .nest("/organizations", organization::router())
        .with_state(state)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    // Log the matched route's path (with placeholders not filled in).
                    // Use request.uri() or OriginalUri if you want the real path.
                    let matched_path = request
                        .extensions()
                        .get::<MatchedPath>()
                        .map(MatchedPath::as_str);

                    info_span!(
                        "http_request",
                        method = ?request.method(),
                        matched_path,
                        some_other_field = tracing::field::Empty,
                    )
                })
                .on_request(|request: &Request<_>, _span: &Span| {
                    // You can use `_span.record("some_other_field", value)` in one of these
                    // closures to attach a value to the initially empty field in the info_span
                    // created above.

                    tracing::debug!("Headers: {:?}", request.headers());
                })
                .on_response(|response: &Response, latency: Duration, _span: &Span| {
                    // Fires once the headers are ready, so the body has not streamed yet.
                    tracing::debug!(status = %response.status(), ?latency, "Response");
                })
                .on_eos(
                    |_trailers: Option<&HeaderMap>, _stream_duration: Duration, _span: &Span| {
                        // ...
                    },
                )
                .on_failure(
                    |_error: ServerErrorsFailureClass, _latency: Duration, _span: &Span| {
                        // ...
                    },
                ),
        )
        // Outermost, so the headers are already marked when TraceLayer logs them: their values
        // print as `Sensitive` instead of the bearer token.
        .layer(SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
            header::COOKIE,
        ]))
}

/// Configures every dependency and settles all configuration.
async fn build_state(
    oauth2_url: &str,
    database_url: &str,
    audience: &str,
    transport: Transport,
) -> AppState {
    // Keycloak is called while verifying tokens, so a hung Keycloak must fail those requests
    // instead of holding them open.
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .build()
        .expect("Failed to build the HTTP client");
    let keycloak_jwt_verifier =
        KeycloakJwtVerifier::new(oauth2_url, client, audience.to_string(), transport)
            .await
            .expect("Failed to read the Keycloak well-known configuration");
    let verifier = Arc::new(keycloak_jwt_verifier);

    let authorization_service = Arc::new(AuthAPIAuthorizationService);
    // Local Event Sourcing
    let event_emitter = Arc::new(TokioEventBus::new());

    // DatabaseState
    let database_state = database_setup(database_url).await.unwrap();

    let organization = organization::OrganizationState::new(
        authorization_service,
        event_emitter,
        Arc::new(database_state.organization_write_repository),
    );

    AppState::new(verifier, organization)
}
