use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::{error, info};

mod config;
mod error;
mod protocol;
mod proxy;
mod server;
mod tls;

use config::Config;
use server::Server;
use tls::TlsConfig;

#[derive(Parser, Debug)]
#[command(name = "trojan-rust")]
#[command(about = "A lightweight, high-performance Trojan proxy server")]
struct Args {
    #[arg(short, long, value_name = "FILE", default_value = "config/config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let config = match Config::from_file(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };

    init_tracing(&config.log_level);

    info!("Starting trojan-rust server");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));
    info!("Bind address: {}", config.bind_addr);

    let tls_config = match TlsConfig::new(&config.tls_cert, &config.tls_key) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to initialize TLS: {}", e);
            std::process::exit(1);
        }
    };

    let server = Server::new(config, tls_config);

    if let Err(e) = server.run().await {
        error!("Server error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}

fn init_tracing(log_level: &str) {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();
}
