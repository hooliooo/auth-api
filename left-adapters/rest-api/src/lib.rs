use auth_core::{
    application::organization::command_factory::OrganizationCommandFactory,
    domain::authorization::AuthAPIAuthorizationService,
};
use kern::{
    application::environment::Environment, infrastructure::event::event_bus::TokioEventBus,
};
use std::{env, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use write_model::database_setup;

use axum::{
    Router,
    body::Bytes,
    extract::MatchedPath,
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use tower_http::{classify::ServerErrorsFailureClass, trace::TraceLayer};
use tracing::{Span, info_span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    authorization::jwt::KeycloakJwtVerifier,
    organization::{OrganizationState, router::create_organization_state},
};

pub mod authorization;
pub mod organization;

pub async fn create_router() -> Router {
    let state = create_app_state().await;
    // Create Routers
    let organization_router =
        organization::router::create_organization_router(state.organization.create.clone());
    let health_router = Router::new().route("/", get(health));

    Router::new()
        .nest("/health", health_router)
        .nest("/organizations", organization_router)
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
                .on_response(|_response: &Response, _latency: Duration, _span: &Span| {
                    // ...
                })
                .on_body_chunk(|_chunk: &Bytes, _latency: Duration, _span: &Span| {
                    // ...
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
}

pub async fn run(listener: TcpListener) -> Result<(), std::io::Error> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // axum logs rejections from built-in extractors with the `axum::rejection`
                // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                format!(
                    "{}=debug,tower_http=debug,axum::rejection=trace",
                    env!("CARGO_CRATE_NAME")
                )
                .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    let app = create_router().await;
    let address = listener.local_addr().unwrap();
    tracing::debug!("listening on {}", address);
    axum::serve(listener, app).await
}

async fn health() -> Response {
    StatusCode::OK.into_response()
}

#[derive(Clone)]
pub struct AppState {
    organization: OrganizationState,
}

/// Create the AppState for the application
/// Configure all dependencies and settle all configuration
async fn create_app_state() -> AppState {
    // Load the environment variables
    dotenvy::dotenv().unwrap();
    let keycloak_url = env::var("OAUTH2_BASE_URL").unwrap();
    let audience = env::var("AUDIENCE").unwrap();
    let database_url = env::var("DATABASE_URL").unwrap();

    // Create the JWTVerifier
    let client = reqwest::Client::new();
    let keycloak_jwt_verifier = KeycloakJwtVerifier::new(
        format!("{}/.well-known/openid-configuration", keycloak_url),
        client,
        audience,
        true,
    )
    .await;
    let verifier = Arc::new(keycloak_jwt_verifier);

    let authorization_service = Arc::new(AuthAPIAuthorizationService);
    let environment = Environment::Development;
    // Local Event Sourcing
    let event_emitter = Arc::new(TokioEventBus::new());

    // DatabaseState
    let database_state = database_setup(&database_url).await.unwrap();

    // Create OrganizationState
    let organization_state = create_organization_state(
        authorization_service,
        verifier.clone(),
        event_emitter,
        Arc::new(OrganizationCommandFactory::new(environment)),
        Arc::new(database_state.organization_write_repository),
    );

    AppState {
        organization: organization_state,
    }
}
