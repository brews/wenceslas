mod core;
mod storage;

use crate::{
    core::{GetUserError, UnverifiedPassword, UserEmail, UserProfile, VerifyError},
    storage::HashStorage,
};
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use log::warn;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use std::{fs::File, sync::Arc};
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{debug, info, level_filters::LevelFilter};
use tracing_subscriber::EnvFilter;

// TODO: Move web logic to its own module.
// TODO: Improve web logic test coverage.
// TODO: Improve ERROR logging, especially w.r.t. `anyhow`.
// TODO: Make number of workers/threads configurable.
// TODO: Make timeout configurable.
// TODO: Structured logging. Request IDs.
// TODO: Formalize fuzz testing, maybe property testing
// TODO: Basic benchmarks.

#[derive(Deserialize)]
struct VerifyRequest {
    email: UserEmail,
    password: UnverifiedPassword,
}

struct AppState {
    store: HashStorage,
    apikey: Option<String>,
}

#[derive(Debug)]
pub enum VerifyDecision {
    Verified,
    Unverified,
}

#[derive(Deserialize)]
struct GetUserRequest {
    email: UserEmail,
}

impl IntoResponse for VerifyDecision {
    fn into_response(self) -> Response {
        let decision = match self {
            VerifyDecision::Verified => true,
            VerifyDecision::Unverified => false,
        };

        let body = Json(json!({ "verified": decision }));
        (StatusCode::OK, body).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    // Set default logging level, but can override from env var.
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::TRACE.into())
        .from_env_lossy();
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
    info!("starting server");

    // Read and parse settings.
    let csv_path =
        std::env::var("CSV_PATH").expect("required CSV_PATH environment variable is not set");
    let host = std::env::var("HOST").expect("required HOST environment variable is not set");
    let port = std::env::var("PORT").expect("required PORT environment variable is not set");
    let apikey: Option<String> = std::env::var("APIKEY").ok();
    let server_url = format!("{host}:{port}");

    debug!("loading storage");
    let file = File::open(&csv_path)?;
    // Store in Arc so data isn't copied on every request, only a pointer is copied.
    let store = storage::load_storage(file)?;
    info!("storage loaded from {csv_path}");

    if apikey.is_some() {
        info!("found apikey, enabling auth check for requests");
    } else {
        info!("no apikey found, disabling auth check for requests");
    }
    // TODO: Consider breaking appstate in two, as each member only needed in one place.
    let appstate = Arc::new(AppState { store, apikey });

    let app = Router::new()
        .route("/users", get(get_user))
        .route("/verify", post(post_verify))
        .layer(TimeoutLayer::new(Duration::from_secs(30))) // TODO: Test this does its job.
        .layer(middleware::from_fn_with_state(appstate.clone(), auth))
        .layer(TraceLayer::new_for_http())
        .with_state(appstate);
    debug!("routes set up");

    info!("listening on {server_url:?}");
    let listener = tokio::net::TcpListener::bind(server_url)
        .await
        .context("Could not bind server to the address and port")?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Could not serve application")?;
    Ok(())
}

async fn post_verify(
    State(appstate): State<Arc<AppState>>,
    Json(request): Json<VerifyRequest>,
) -> Result<VerifyDecision, StatusCode> {
    info!("received request verify {:?}", request.email);
    let verify_result = core::verify(&request.email, request.password, &appstate.store);
    // Parse verification results, log errors, respond to request with with decision.
    let decision = match verify_result {
        Ok(_) => VerifyDecision::Verified,
        Err(VerifyError::UnknownEmail) => {
            info!("no records found for {:?}", request.email);
            VerifyDecision::Unverified
        }
        Err(VerifyError::Password) => {
            info!("could not verify password for {:?}", request.email);
            VerifyDecision::Unverified
        }
        Err(VerifyError::Algorithm(e)) => {
            // Warn because recovered from error but might be an issue with stored hash or app bug.
            warn!(
                "encountered error verifying password for {:?}: {e}",
                request.email
            );
            VerifyDecision::Unverified
        }
    };

    info!("decision for {:?} is {decision:?}", request.email);
    Ok(decision)
}

async fn get_user(
    State(appstate): State<Arc<AppState>>,
    Query(params): Query<GetUserRequest>,
) -> Result<Json<UserProfile>, StatusCode> {
    info!("received request for user profile {:?}", params.email);
    let user_profile_result = core::get_user_profile(&params.email, &appstate.store);

    // Digesting these with a match so we can log the outcome.
    match user_profile_result {
        Ok(r) => Ok(Json(r)),
        Err(GetUserError::UnknownEmail) => {
            info!("no records found for {:?}", params.email);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

/// Middleware to screen access to routes based on key in authorization header.
async fn auth(
    State(appstate): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get apikey from app state, return early if None, because then app isn't doing auth.
    let stored_apikey: &str = match &appstate.apikey {
        Some(k) => k.as_str(),
        None => {
            info!("no APIKEY set, skipping auth");
            return Ok(next.run(req).await);
        }
    };

    // Get api key from header.
    let auth_header = req
        .headers()
        .get("x-apikey")
        .and_then(|header| header.to_str().ok());
    let auth_header = if let Some(auth_header) = auth_header {
        auth_header
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    // Check header against valid key.
    if auth_header == stored_apikey {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Prepares server to gracefully handle shutdown signals.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
