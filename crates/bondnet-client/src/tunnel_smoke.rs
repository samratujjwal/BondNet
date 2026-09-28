//! Dev-only Day 9 tunnel smoke test: Wintun → BondNet Data → UDP → VPS.
//!
//! ```text
//! bondnet-client tunnel-smoke --local 192.168.0.170:0 --remote VPS:51820 \
//!   --path-id 1 --session-id 1001 [--adapter BondNet] [--verbose]
//! ```
//!
//! Mode A (`--synthetic`): no Wintun involved. Deterministic synthetic
//! IPv4/UDP packets of several sizes flow through `DataPlane` → UDP →
//! server. Portable — runs on Linux too. Proves protocol + transport +
//! server without the virtual adapter.
//!
//! Mode B (default, Windows only): a dedicated blocking thread reads the
//! real Wintun ring (`wait_for_packet`, never busy-spin) and pushes
//! packets into a bounded Tokio mpsc channel
//! (`DATA_PLANE_CHANNEL_CAPACITY`); the async task drains the channel
//! through `DataPlane::send_wintun_packet`. The blocking Wintun wait
//! never runs on a Tokio executor thread (Option A from the brief).
//!
//! # Routing-recursion invariant
//!
//! The UDP socket is bound to the explicit physical local address (Day 7)
//! and NEVER to the Wintun adapter. Wintun is only the source of inner
//! packets, never the tunnel's egress. No routes, DNS, MTU or NAT are
//! touched.

use bondnet_client::data_plane::DataPlane;
use bondnet_client::synthetic;
use bondnet_client::{UdpPath, UdpPathConfig};

// The Wintun data path (Mode B) only exists on Windows; these imports
// are gated so the portable synthetic mode stays warning-free on Linux.
#[cfg(windows)]
use bondnet_client::data_plane::DATA_PLANE_CHANNEL_CAPACITY;
#[cfg(windows)]
use std::sync::Arc;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(windows)]
use std::time::Duration;

/// Inner-packet sizes (bytes, including the 28-byte IPv4/UDP headers)
/// cycled through in synthetic mode: normal sizes up to 1500-byte-class.
const SYNTHETIC_SIZES: [usize; 5] = [64, 512, 1200, 1400, 1500];

struct TunnelArgs {
    config: UdpPathConfig,
    // Only read by the Windows Wintun mode; kept in the struct so both
    // modes share one parser.
    #[cfg_attr(not(windows), allow(dead_code))]
    adapter_name: String,
    synthetic: bool,
    synthetic_count: u64,
    verbose: bool,
}

/// Parse the words after `tunnel-smoke`. Separate from the Day 7 parser
/// so the old command's behavior stays exactly as validated.
fn parse_tunnel_args(args: &[String]) -> Result<TunnelArgs, String> {
    let mut local: Option<std::net::SocketAddr> = None;
    let mut remote: Option<std::net::SocketAddr> = None;
    let mut path_id: Option<u16> = None;
    let mut session_id: Option<u64> = None;
    let mut adapter_name = bondnet_client::wintun::DEFAULT_ADAPTER_NAME.to_string();
    let mut synthetic = false;
    let mut synthetic_count: u64 = 5;
    let mut verbose = false;

    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--local" => {
                let v = rest
                    .next()
                    .ok_or_else(|| "--local requires an address".to_string())?;
                local = Some(
                    v.parse()
                        .map_err(|_| format!("invalid --local address: {v}"))?,
                );
            }
            "--remote" => {
                let v = rest
                    .next()
                    .ok_or_else(|| "--remote requires an address".to_string())?;
                remote = Some(
                    v.parse()
                        .map_err(|_| format!("invalid --remote address: {v}"))?,
                );
            }
            "--path-id" => {
                let v = rest
                    .next()
                    .ok_or_else(|| "--path-id requires a number".to_string())?;
                path_id = Some(v.parse().map_err(|_| format!("invalid --path-id: {v}"))?);
            }
            "--session-id" => {
                let v = rest
                    .next()
                    .ok_or_else(|| "--session-id requires a number".to_string())?;
                session_id = Some(
                    v.parse()
                        .map_err(|_| format!("invalid --session-id: {v}"))?,
                );
            }
            "--adapter" => {
                adapter_name = rest
                    .next()
                    .ok_or_else(|| "--adapter requires a name".to_string())?
                    .clone();
            }
            "--synthetic" => synthetic = true,
            "--synthetic-count" => {
                let v = rest
                    .next()
                    .ok_or_else(|| "--synthetic-count requires a number".to_string())?;
                synthetic_count = v
                    .parse()
                    .map_err(|_| format!("invalid --synthetic-count: {v}"))?;
                if synthetic_count == 0 {
                    return Err("--synthetic-count must be at least 1".to_string());
                }
            }
            "--verbose" => verbose = true,
            other => return Err(format!("unknown tunnel-smoke argument: {other}")),
        }
    }

    let local_addr = local.ok_or_else(|| "--local is required".to_string())?;
    if !local_addr.ip().is_ipv4() {
        return Err(format!(
            "tunnel-smoke binds an explicit local IPv4 address; got {local_addr}"
        ));
    }
    Ok(TunnelArgs {
        config: UdpPathConfig {
            path_id: path_id.ok_or_else(|| "--path-id is required".to_string())?,
            session_id: session_id.ok_or_else(|| "--session-id is required".to_string())?,
            local_addr,
            remote_addr: remote.ok_or_else(|| "--remote is required".to_string())?,
            initial_sequence: 1,
        },
        adapter_name,
        synthetic,
        synthetic_count,
        verbose,
    })
}

/// Run the smoke test. `args` are the CLI words after `tunnel-smoke`.
pub async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let parsed = parse_tunnel_args(args).map_err(|e| {
        format!(
            "{e}\nusage: bondnet-client tunnel-smoke --local ADDR:PORT --remote ADDR:PORT \
             --path-id N --session-id N [--adapter NAME] [--synthetic] [--synthetic-count N] [--verbose]"
        )
    })?;

    println!(
        "WARNING: BondNet Day 9 is plaintext (no encryption yet). Development use only — send harmless test payloads, never secrets."
    );

    if parsed.synthetic {
        run_synthetic(parsed).await
    } else {
        run_wintun(parsed).await
    }
}

/// Mode A: deterministic synthetic packets through the data plane. No
/// Wintun, portable, proves protocol + transport + server.
async fn run_synthetic(parsed: TunnelArgs) -> Result<(), Box<dyn std::error::Error>> {
    let path = UdpPath::bind(parsed.config).await?;
    println!(
        "tunnel-smoke (synthetic): local={} remote={} session={} path={}",
        path.local_addr()?,
        path.remote_addr(),
        path.session_id(),
        path.path_id(),
    );
    let plane = DataPlane::new(path);

    for i in 0..parsed.synthetic_count {
        let inner_len = SYNTHETIC_SIZES[(i as usize) % SYNTHETIC_SIZES.len()];
        // 28 = IPv4 header (20) + UDP header (8).
        let payload = deterministic_payload(inner_len - 28, i);
        let packet = synthetic::ipv4_udp_test_packet(&payload);
        debug_assert_eq!(packet.len(), inner_len);
        let seq = plane.send_wintun_packet(&packet).await?;
        if parsed.verbose || i < 3 || i + 1 == parsed.synthetic_count {
            println!("sent synthetic inner={inner_len}B seq={seq}");
        }
    }

    let m = plane.metrics_snapshot();
    println!(
        "done: tunnel_packets_sent={} tunnel_bytes_sent={} send_errors={} oversized_dropped={}",
        m.tunnel_packets_sent, m.tunnel_bytes_sent, m.send_errors, m.oversized_dropped
    );
    Ok(())
}

/// Deterministic per-packet payload: distinct bytes per packet index so a
/// byte-exact server comparison can tell packets apart.
fn deterministic_payload(len: usize, index: u64) -> Vec<u8> {
    (0..len)
        .map(|j| (index as u8).wrapping_add(j as u8).wrapping_mul(31))
        .collect()
}

/// Mode B: real Wintun packets through the data plane (Windows only).
#[cfg(windows)]
async fn run_wintun(parsed: TunnelArgs) -> Result<(), Box<dyn std::error::Error>> {
    use bondnet_client::wintun::{
        DEFAULT_RING_CAPACITY, WintunAdapter, WintunLibrary, WintunSession,
    };
    use tokio::sync::mpsc;

    let lib = WintunLibrary::load()?;
    println!("Wintun DLL: loaded");
    let adapter = WintunAdapter::open_or_create(&lib, &parsed.adapter_name)?;
    println!("Adapter: {} (opened or created)", parsed.adapter_name);

    // The tunnel socket binds the PHYSICAL address — never Wintun. This
    // binding is the routing-recursion guard: tunnel UDP leaves through
    // the real interface, inner packets come from Wintun.
    let path = UdpPath::bind(parsed.config).await?;
    let actual_local = path.local_addr()?;
    println!(
        "Tunnel UDP: {actual_local} -> {} (physical interface)",
        path.remote_addr()
    );
    if actual_local.ip() != path.configured_local_addr().ip() {
        eprintln!(
            "WARNING: bound local IP {} differs from configured {}",
            actual_local.ip(),
            path.configured_local_addr().ip()
        );
    }

    let plane = DataPlane::new(path);
    let metrics = Arc::clone(plane.metrics());

    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let flag = Arc::clone(&shutdown);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            flag.store(true, Ordering::SeqCst);
        });
    }

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(DATA_PLANE_CHANNEL_CAPACITY);

    // Async sender task: the ONLY code that touches the UDP socket.
    // Send failures are counted and logged; the loop keeps draining.
    let verbose = parsed.verbose;
    let sender = tokio::spawn(async move {
        let mut sent = 0u64;
        while let Some(packet) = rx.recv().await {
            match plane.send_wintun_packet(&packet).await {
                Ok(seq) => {
                    sent += 1;
                    if verbose && sent % 50 == 1 {
                        println!("tunnel sent inner={}B seq={seq}", packet.len());
                    }
                }
                Err(error) => eprintln!("data-plane send failed: {error}"),
            }
        }
    });

    // Blocking Wintun reader on a dedicated OS thread (brief Option A).
    // `thread::scope` lets the session borrow `adapter` without 'static;
    // `block_in_place` keeps the blocking wait off Tokio worker threads.
    let reader_flag = Arc::clone(&shutdown);
    let reader_metrics = Arc::clone(&metrics);
    let reader_result = tokio::task::block_in_place(|| {
        let mut session = WintunSession::start(&adapter, DEFAULT_RING_CAPACITY)
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        println!("Session: started (ring capacity {DEFAULT_RING_CAPACITY})");
        println!("Reading Wintun packets... (Ctrl+C to stop)");
        std::thread::scope(|scope| {
            let handle = scope.spawn(move || {
                wintun_reader_loop(&mut session, tx, &reader_flag, &reader_metrics);
                // `session` drops here: the Wintun session ends while the
                // adapter is still alive — the required teardown order.
            });
            // Wait for Ctrl+C or for the reader thread to die on its own;
            // either way we then join it and let the channel close.
            while !shutdown.load(Ordering::SeqCst) && !handle.is_finished() {
                std::thread::sleep(Duration::from_millis(100));
            }
            match handle.join() {
                Ok(()) => {}
                Err(_) => eprintln!("WARNING: wintun reader thread panicked"),
            }
        });
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    reader_result?;

    // The reader dropped its `tx`: the channel closes, the sender drains
    // whatever is left, then `recv()` returns None and the task ends.
    // No deadlock: the reader never blocks on a full channel (try_send).
    if let Err(error) = sender.await {
        eprintln!("WARNING: sender task failed: {error}");
    }

    let m = metrics.snapshot();
    println!(
        "tunnel-smoke done: wintun_packets_read={} tunnel_packets_sent={} tunnel_bytes_sent={} \
         send_errors={} oversized_dropped={} invalid_dropped={} backpressure_dropped={}",
        m.wintun_packets_read,
        m.tunnel_packets_sent,
        m.tunnel_bytes_sent,
        m.send_errors,
        m.oversized_dropped,
        m.invalid_dropped,
        m.backpressure_dropped,
    );
    // `adapter` drops here, after the session already ended above.
    println!("Adapter: closed");
    println!("Exiting cleanly.");
    Ok(())
}

/// Blocking Wintun read loop. Runs on its own OS thread — never on a
/// Tokio executor thread. `session` is `&mut` from this thread only.
#[cfg(windows)]
fn wintun_reader_loop(
    session: &mut bondnet_client::wintun::WintunSession,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    shutdown: &AtomicBool,
    metrics: &bondnet_client::data_plane::DataPlaneMetrics,
) {
    use tokio::sync::mpsc::error::TrySendError;

    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        match session.wait_for_packet(Duration::from_millis(100)) {
            Ok(true) => {
                // The read event fired: drain everything in the ring.
                loop {
                    if shutdown.load(Ordering::SeqCst) {
                        return;
                    }
                    match session.recv_packet() {
                        Ok(Some(packet)) => {
                            metrics.wintun_packets_read.fetch_add(1, Ordering::Relaxed);
                            match tx.try_send(packet) {
                                Ok(()) => {}
                                Err(TrySendError::Full(_)) => {
                                    // Bounded backpressure: drop the newest
                                    // packet and count it. Never block the
                                    // reader, never grow memory.
                                    metrics.backpressure_dropped.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(TrySendError::Closed(_)) => return,
                            }
                        }
                        Ok(None) => break, // ring drained; back to the wait event
                        Err(error) => {
                            eprintln!("wintun receive failed: {error}");
                            break;
                        }
                    }
                }
            }
            Ok(false) => {} // timeout: re-check the shutdown flag
            Err(error) => {
                eprintln!("wintun wait failed: {error}");
                break;
            }
        }
    }
}

/// Mode B on non-Windows: an honest error, not a fake Wintun.
#[cfg(not(windows))]
async fn run_wintun(_parsed: TunnelArgs) -> Result<(), Box<dyn std::error::Error>> {
    Err("tunnel-smoke without --synthetic needs Windows (real Wintun); use --synthetic on this platform".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn full() -> Vec<String> {
        args(&[
            "--local",
            "192.168.0.170:0",
            "--remote",
            "203.0.113.10:51820",
            "--path-id",
            "1",
            "--session-id",
            "1001",
        ])
    }

    #[test]
    fn full_args_parse() {
        let parsed = parse_tunnel_args(&full()).unwrap();
        assert_eq!(parsed.config.path_id, 1);
        assert_eq!(parsed.config.session_id, 1001);
        assert_eq!(parsed.adapter_name, "BondNet");
        assert!(!parsed.synthetic);
        assert_eq!(parsed.synthetic_count, 5);
        assert!(!parsed.verbose);
    }

    #[test]
    fn synthetic_flag_parses() {
        let mut a = full();
        a.push("--synthetic".to_string());
        a.extend(["--synthetic-count".to_string(), "3".to_string()]);
        let parsed = parse_tunnel_args(&a).unwrap();
        assert!(parsed.synthetic);
        assert_eq!(parsed.synthetic_count, 3);
    }

    #[test]
    fn missing_required_args_rejected() {
        assert!(parse_tunnel_args(&args(&[])).is_err());
        assert!(
            parse_tunnel_args(&args(&[
                "--local",
                "192.168.0.170:0",
                "--remote",
                "203.0.113.10:51820",
            ]))
            .is_err()
        );
    }

    #[test]
    fn zero_synthetic_count_rejected() {
        let mut a = full();
        a.extend(["--synthetic-count".to_string(), "0".to_string()]);
        assert!(parse_tunnel_args(&a).is_err());
    }

    #[test]
    fn non_ipv4_local_rejected() {
        let mut a = full();
        a[1] = "[::1]:0".to_string();
        assert!(parse_tunnel_args(&a).is_err());
    }

    #[test]
    fn unknown_argument_rejected() {
        let mut a = full();
        a.push("--nope".to_string());
        assert!(parse_tunnel_args(&a).is_err());
    }

    #[test]
    fn deterministic_payload_differs_per_index() {
        let a = deterministic_payload(64, 0);
        let b = deterministic_payload(64, 1);
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }
}
