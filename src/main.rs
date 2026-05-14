mod config;
mod dynblock;
mod handler;
mod matcher;
mod ranges;

use axum::{routing::post, Router};
use clap::Parser;
use handler::AppState;
use std::path::PathBuf;
use std::sync::Arc;

const DEFAULT_CONFIG: &str = "/etc/frps-defender/config.json";

#[derive(Parser)]
#[command(name = "frps-defender", about = "frp server plugin: block connections by IP range")]
struct Args {
    /// Path to JSON config file
    #[arg(long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let config = match args.config {
        Some(path) => config::Config::load(&path, true)?,
        None => config::Config::load(&PathBuf::from(DEFAULT_CONFIG), false)?,
    };

    let listen: std::net::SocketAddr = config.listen.parse()?;
    let matcher = matcher::Matcher::build();
    let state = Arc::new(AppState { config, matcher });

    let app = Router::new()
        .route("/handler", post(handler::handle))
        .with_state(state);

    tracing::info!("listening on {}", listen);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
