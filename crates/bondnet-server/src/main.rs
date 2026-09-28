//! `bondnet-server` binary: parse CLI, warn about plaintext, run.

use std::sync::Arc;

use bondnet_server::{Server, parse_args};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let config = match parse_args(&args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {error}");
            eprintln!("usage: bondnet-server [--bind ADDR:PORT] [--verbose]");
            std::process::exit(2);
        }
    };

    // Day 6 honesty: this speaks the BondNet protocol WITHOUT encryption.
    // Crypto integration is a later milestone. Development use only.
    println!(
        "WARNING: BondNet Day 6 is plaintext (no encryption yet). Development use only — not a production VPN server."
    );

    let server = Arc::new(Server::new(config));
    let shutdown = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            eprintln!("failed to listen for Ctrl+C: {error}; running until killed");
            std::future::pending::<()>().await;
        }
    };
    if let Err(error) = server.run(shutdown).await {
        eprintln!("server error: {error}");
        std::process::exit(1);
    }
}
