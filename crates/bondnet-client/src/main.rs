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
//! not a service, and
//!
//! ```text
//! bondnet-client path-diag --session-id 1001 \
//!   --path1-id 1 --path1-local 192.168.1.10:0 --path1-remote VPS:51820 \
//!   --path2-id 2 --path2-local 192.168.2.10:0 --path2-remote VPS:51820
//! ```
//!
//! runs the Day 13 two-path diagnostic: initializes two independent UDP
//! paths, reports each path's endpoints, sends one PathHello per path,
//! then shuts down cleanly.

mod path_diag;
#[cfg(windows)]
mod smoke;
mod tunnel_smoke;

use bondnet_client::bench;
use bondnet_client::health_diag;

use bondnet_client::{UdpPath, parse_args, parse_psk_hex};
use bondnet_protocol::PacketType;

/// Day 20: like [`parse_args`](bondnet_client::parse_args) but also
/// accepts `--psk HEX`. The PSK is stripped before delegating so the
/// base parser's behavior is unchanged.
fn parse_args_psk(
    args: &[String],
) -> Result<
    (
        bondnet_client::UdpPathConfig,
        u64,
        bool,
        Option<bondnet_crypto::CryptoKey>,
    ),
    String,
> {
    let mut filtered: Vec<String> = Vec::with_capacity(args.len());
    filtered.push(args[0].clone());
    let mut psk: Option<bondnet_crypto::CryptoKey> = None;
    let mut rest = args.iter().skip(1).peekable();
    while let Some(arg) = rest.next() {
        if arg == "--psk" {
            let v = rest
                .next()
                .ok_or_else(|| "--psk requires a 64-char hex string".to_string())?;
            psk = Some(parse_psk_hex(v)?);
        } else {
            filtered.push(arg.clone());
        }
    }
    let (config, count, verbose) = parse_args(&filtered)?;
    Ok((config, count, verbose, psk))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = if args.get(1).is_some_and(|first| first == "wintun-smoke") {
        run_wintun_smoke(&args).await
    } else if args.get(1).is_some_and(|first| first == "tunnel-smoke") {
        tunnel_smoke::run(&args[2..]).await
    } else if args.get(1).is_some_and(|first| first == "path-diag") {
        path_diag::run(&args[2..]).await
    } else if args.get(1).is_some_and(|first| first == "bench") {
        bench::run_bench(&args[2..]).await
    } else if args.get(1).is_some_and(|first| first == "health-diag") {
        health_diag::run(&args[2..]).await
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
    let (config, count, verbose, psk) =
        parse_args_psk(args).map_err(|e| format!("{e}\nusage: bondnet-client --local ADDR:PORT --remote ADDR:PORT --path-id N --session-id N [--count N] [--psk HEX] [--verbose]"))?;

    let path = UdpPath::bind(config).await?;

    // Day 20: attach encryption when --psk is given. The session gets a
    // fresh random salt; the salt travels in the PathHello payload so the
    // server derives matching keys.
    match psk {
        Some(key) => {
            let s = std::sync::Arc::new(
                bondnet_crypto::SecureSession::new_with_random_salt(&key, path.session_id())
                    .map_err(|e| format!("failed to derive session keys: {e}"))?,
            );
            path.set_secure_session(s);
            println!(
                "encryption: ENABLED (XChaCha20-Poly1305, session salt exchanged via PathHello)"
            );
        }
        None => {
            println!(
                "WARNING: no --psk given, traffic is plaintext. Development use only — send harmless test payloads, never secrets."
            );
        }
    };
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
            // Day 20: PathHello carries the 32-byte session salt when
            // encryption is on, so the server derives matching keys.
            PacketType::PathHello => path.secure_salt().map(|s| s.to_vec()).unwrap_or_default(),
            _ => Vec::new(),
        };
        // Day 15: explicit session-wide sequence (i+1). This is the legacy
        // single-path burst mode; the sequence is the logical order.
        let sequence = path.send_new(packet_type, payload, i + 1).await?;
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
