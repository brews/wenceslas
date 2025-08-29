mod storage;

use crate::storage::{HashStorage, load_storage};
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use std::{fs::File, sync::Arc};
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{debug, info, level_filters::LevelFilter};
use tracing_subscriber::EnvFilter;

#[derive(Deserialize)]
struct VerifyRequest {
    email: String,
    password: String,
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
    // TODO: Log INFO saying when apikey is set on startup.
    let server_url = format!("{host}:{port}");

    debug!("loading storage");
    let file = File::open(&csv_path)?;
    // Store in Arc so data isn't copied on every request, only a pointer is copied.
    let store = load_storage(file)?;
    info!("storage loaded from {csv_path}");

    // TODO: Consider breaking appstate in two, as each member only needed in one place.

    let appstate = Arc::new(AppState { store, apikey });

    let app = Router::new()
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
    Json(payload): Json<VerifyRequest>,
) -> Result<VerifyDecision, StatusCode> {
    let email: String = payload.email;
    let password: &[u8] = payload.password.as_bytes();
    info!("received request verify {email}");

    // Find hash in storage matching user email.
    let hash_result = appstate.store.read_user_hash(&email);
    let user_hash = match hash_result {
        Some(r) => r,
        None => {
            debug!("no records found for {email}");
            let decision = VerifyDecision::Unverified;
            info!("Decision for {email} is {decision:?}");
            return Ok(decision);
        }
    };
    debug!("read record from storage");
    info!("found record for {email}");

    // Verify password against stored hash.
    let decision = match wenceslas::verify_password(user_hash, password) {
        true => VerifyDecision::Verified,
        false => VerifyDecision::Unverified,
    };
    info!("Decision for {email} is {decision:?}");

    Ok(decision)
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
