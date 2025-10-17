mod config;
mod core;
mod service;
mod storage;
mod web;

use crate::config::Config;
use crate::service::Service;
use crate::web::HttpServer;
use anyhow::Result;
use std::{fs::File, sync::Arc};
use tracing::{debug, info, level_filters::LevelFilter};
use tracing_subscriber::EnvFilter;

// TODO: Need type for Config.apikey so can't log accidentally.
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

    let config = Config::load();

    debug!("loading storage");
    let file = File::open(&config.csv_path)?;
    let store = storage::load_storage(file)?;
    info!("storage loaded from {}", config.csv_path);

    if config.apikey.is_some() {
        info!("found apikey, enabling auth check for requests");
    } else {
        info!("no apikey found, disabling auth check for requests");
    }

    let app_service = Arc::new(Service::new(store));
    let apikey = Arc::new(config.apikey);

    let server = HttpServer::new(app_service, config.host, config.port, apikey).await?;
    server.run().await
}
