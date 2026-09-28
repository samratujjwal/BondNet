//! `bondnet-client` dev CLI.
//!
//! Three modes, selected by the first argument:
//!
//! ```text
//! bondnet-client --local 192.168.0.170:0 --remote VPS:51820 \
//!   --path-id 1 --session-id 1001 --count 5 --verbose
//! ```
//!
//! sends a finite burst of test packets over one physical path (Day 7),
//! while
//!
//! ```text
//! bondnet-client wintun-smoke [--adapter NAME] [--send-test]
//! ```
//!
//! runs the dev-only Wintun virtual-adapter smoke test (Day 8, Windows
//! only), and
//!
//! ```text
//! bondnet-client tunnel-smoke --local 192.168.0.170:0 \
//!   --remote VPS:51820 --path-id 1 --session-id 1001 \
//!   [--adapter NAME] [--synthetic] [--verbose]
//! ```
//!
//! runs the Day 9 tunnel smoke test: Wintun → BondNet Data packet → UDP
//! path → VPS (`--synthetic` skips Wintun and is portable). Not a daemon,
//! not a service.

#[cfg(windows)]
mod smoke;
mod tunnel_smoke;

use bondnet_client::{UdpPath, parse_args};
use bondnet_protocol::PacketType;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = if args.get(1).is_some_and(|first| first == "wintun-smoke") {
        run_wintun_smoke(&args).await
    } else if args.get(1).is_some_and(|first| first == "tunnel-smoke") {
        tunnel_smoke::run(&args[2..]).await
    } else {
        run_path_client(&args).await
    };
    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

/// Day 8 dev smoke test. Only exists on Windows; elsewhere it is a clean
/// error instead of a missing subcommand.
#[cfg(windows)]
async fn run_wintun_smoke(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    smoke::run(&args[2..]).await
}

#[cfg(not(windows))]
async fn run_wintun_smoke(_args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    Err("wintun-smoke is only available on Windows".into())
}

async fn run_path_client(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (config, count, verbose) = parse_args(args).map_err(|e| format!("{e}\nusage: bondnet-client --local ADDR:PORT --remote ADDR:PORT --path-id N --session-id N [--count N] [--verbose]"))?;

    println!(
        "WARNING: BondNet Day 7 is plaintext (no encryption yet). Development use only — send harmless test payloads, never secrets."
    );

    let path = UdpPath::bind(config).await?;
    let actual_local = path.local_addr()?;

    // §25: prove the socket really owns the configured physical address.
    println!("BondNet path started");
    println!("  path_id: {}", path.path_id());
    println!("  session_id: {}", path.session_id());
    println!("  local: {actual_local}");
    println!("  remote: {}", path.remote_addr());
    if actual_local.ip() != path.configured_local_addr().ip() {
        eprintln!(
            "WARNING: bound local IP {} differs from configured {}",
            actual_local.ip(),
            path.configured_local_addr().ip()
        );
    }

    println!("Sending {count} test packets...");
    for i in 0..count {
        let packet_type = if i == 0 {
            PacketType::PathHello
        } else if i == count - 1 {
            PacketType::PathKeepalive
        } else {
            PacketType::Data
        };
        let payload = match packet_type {
            PacketType::Data => format!("bondnet-day7-ping-{i}").into_bytes(),
            _ => Vec::new(),
        };
        let sequence = path.send_new(packet_type, payload).await?;
        println!("seq={sequence} type={packet_type:?}");
        if verbose {
            let stats = path.stats();
            println!("  sent={} bytes={}", stats.packets_sent, stats.bytes_sent);
        }
    }

    let stats = path.stats();
    println!(
        "done: packets_sent={} bytes_sent={}",
        stats.packets_sent, stats.bytes_sent
    );
    Ok(())
}
