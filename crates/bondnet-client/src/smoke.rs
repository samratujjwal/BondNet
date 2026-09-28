//! Dev-only Wintun smoke test.
//!
//! ```text
//! bondnet-client wintun-smoke [--adapter NAME] [--send-test]
//! ```
//!
//! Loads `wintun.dll` (expected beside the executable), prints the driver
//! version, opens-or-creates the adapter, starts a session, optionally
//! proves the send path with one synthetic IPv4/UDP packet, then counts
//! received Layer-3 packets until Ctrl+C. Shutdown is clean: session ends,
//! adapter closes, DLL unloads.
//!
//! No packet payloads are ever logged. No IP, route, DNS or MTU is
//! configured — Day 8 proves the virtual device, not Internet access.
//!
//! ## Manual receive proof
//!
//! With no address on the adapter, Windows delivers no traffic to it. To
//! see `recv_packet` fire for real, assign an address manually in an
//! elevated shell (BondNet itself never does this on Day 8):
//!
//! ```powershell
//! netsh interface ip set address "BondNet" static 10.200.0.1 255.255.255.0
//! ping 10.200.0.1
//! ```
//!
//! The ICMP echo requests then arrive through `WintunReceivePacket`.
//! Remove the address afterwards:
//!
//! ```powershell
//! netsh interface ip set address "BondNet" dhcp
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bondnet_client::wintun::{
    DEFAULT_ADAPTER_NAME, DEFAULT_RING_CAPACITY, WintunAdapter, WintunLibrary, WintunSession,
};

/// Run the smoke test. `args` are the CLI words after `wintun-smoke`.
pub async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut send_test = false;
    let mut adapter_name = DEFAULT_ADAPTER_NAME.to_string();
    let mut words = args.iter();
    while let Some(word) = words.next() {
        match word.as_str() {
            "--send-test" => send_test = true,
            "--adapter" => {
                adapter_name = words.next().ok_or("--adapter needs a name")?.clone();
            }
            other => return Err(format!("unknown wintun-smoke argument: {other}").into()),
        }
    }

    println!("BondNet Wintun smoke test");
    let lib = WintunLibrary::load()?;
    println!("Wintun DLL: loaded");
    let version = lib.driver_version();
    println!(
        "Wintun driver: 0x{version:08x} (v{}.{})",
        version >> 16,
        version & 0xffff
    );

    let adapter = WintunAdapter::open_or_create(&lib, &adapter_name)?;
    println!("Adapter: {adapter_name} (opened or created)");
    let mut session = WintunSession::start(&adapter, DEFAULT_RING_CAPACITY)?;
    println!("Session: started (ring capacity {DEFAULT_RING_CAPACITY})");

    if send_test {
        // NOTE: Wintun does NOT loop sent packets back into the receive
        // ring. This only proves Rust bytes -> AllocateSendPacket ->
        // SendPacket -> OS stack without error. The destination is
        // TEST-NET-1 (192.0.2.1, RFC 5737): guaranteed unroutable, so the
        // stack drops it and nothing reaches the Internet.
        let probe = synthetic_ipv4_udp_packet();
        session.send_packet(&probe)?;
        println!(
            "Send test: {}-byte synthetic IPv4/UDP packet handed to the OS stack (no loopback expected)",
            probe.len()
        );
    }

    println!("Waiting for Layer-3 packets... (Ctrl+C to stop)");
    let running = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&running);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        flag.store(false, Ordering::SeqCst);
    });

    let mut received: u64 = 0;
    let mut bytes: u64 = 0;
    let mut last_report = Instant::now();
    while running.load(Ordering::SeqCst) {
        match session.recv_packet()? {
            Some(packet) => {
                received += 1;
                bytes += packet.len() as u64;
            }
            None => {
                // Ring empty: sleep on Wintun's read event, never busy-loop.
                let _ = session.wait_for_packet(Duration::from_millis(500))?;
            }
        }
        if last_report.elapsed() >= Duration::from_secs(5) {
            println!("... received {received} packets ({bytes} bytes) so far");
            last_report = Instant::now();
        }
    }

    // Explicit drops document the required teardown order: session ends
    // before the adapter closes (the borrow checker enforces it anyway).
    println!("Ctrl+C received: ending session...");
    drop(session);
    println!("Session: ended");
    drop(adapter);
    println!("Adapter: closed");
    println!("Done: received {received} packets ({bytes} bytes). Exiting cleanly.");
    Ok(())
}

/// Minimal valid IPv4/UDP packet aimed at TEST-NET-1 (192.0.2.1, RFC 5737).
/// Used only to exercise the send path; the OS stack drops it.
fn synthetic_ipv4_udp_packet() -> Vec<u8> {
    let payload = b"bondnet-day8-send-test";
    let total_len = 20 + 8 + payload.len();
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45; // version 4, IHL 5
    packet[1] = 0x00; // DSCP/ECN
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // identification
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags: DF
    packet[8] = 64; // TTL
    packet[9] = 17; // protocol: UDP
    packet[12..16].copy_from_slice(&[192, 0, 2, 2]); // src: TEST-NET-1
    packet[16..20].copy_from_slice(&[192, 0, 2, 1]); // dst: TEST-NET-1
    let checksum = ip_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&12345u16.to_be_bytes()); // src port
    packet[22..24].copy_from_slice(&9u16.to_be_bytes()); // dst port: discard
    packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes()); // UDP len
    // UDP checksum left zero (optional for IPv4).
    packet[28..].copy_from_slice(payload);
    packet
}

/// RFC 1071 Internet checksum over a 20-byte IPv4 header.
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
