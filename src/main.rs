mod core;
mod storage;
mod web;

use crate::web::{AppState, HttpServer};
use anyhow::Result;
use std::{fs::File, sync::Arc};
use tracing::{debug, info, level_filters::LevelFilter};
use tracing_subscriber::EnvFilter;

// TODO: Improve web logic test coverage.
// TODO: Improve ERROR logging, especially w.r.t. `anyhow`.
// TODO: Make number of workers/threads configurable.
// TODO: Structured logging. Request IDs.
// TODO: Basic benchmarks.

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

    let server = HttpServer::new(appstate, host, port).await?;
    server.run().await
}
