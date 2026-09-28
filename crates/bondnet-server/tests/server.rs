//! Day 6 integration tests: real UDP datagrams against a real server.
//!
//! No arbitrary sleeps: tests poll the server's atomic counters with a
//! hard timeout, so they stay reliable on Windows dev machines and Linux.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bondnet_protocol::{HEADER_LEN, PROTOCOL_VERSION, Packet, PacketHeader, PacketType};
use bondnet_server::{Server, ServerConfig};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

const POLL_TIMEOUT: Duration = Duration::from_secs(5);

struct RunningServer {
    server: Arc<Server>,
    addr: std::net::SocketAddr,
    shutdown: Arc<Notify>,
    task: JoinHandle<io::Result<()>>,
}

async fn start_server() -> RunningServer {
    let config = ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        verbose: false,
    };
    let server = Arc::new(Server::new(config));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let shutdown = Arc::new(Notify::new());

    let task_server = server.clone();
    let task_shutdown = shutdown.clone();
    let task =
        tokio::spawn(async move { task_server.run_on(socket, task_shutdown.notified()).await });

    RunningServer {
        server,
        addr,
        shutdown,
        task,
    }
}

impl RunningServer {
    async fn stop(self) {
        self.shutdown.notify_one();
        self.task
            .await
            .expect("server task panicked")
            .expect("server returned an error");
    }
}

async fn sender(addr: std::net::SocketAddr) -> UdpSocket {
    // NOTE: this sandbox blocks sendto(2) with EPERM, but connected
    // send(2) works fine. Production code uses send_to; tests connect.
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(addr).await.unwrap();
    socket
}

fn encode_packet(
    session_id: u64,
    path_id: u16,
    sequence: u64,
    packet_type: PacketType,
    payload: Vec<u8>,
) -> Vec<u8> {
    Packet {
        header: PacketHeader {
            version: PROTOCOL_VERSION,
            flags: 0,
            session_id,
            sequence,
            path_id,
            packet_type,
            timestamp: 1_700_000_000_000,
        },
        payload,
    }
    .encode()
    .expect("test packet must encode")
}

/// Poll `condition` until true or `POLL_TIMEOUT` elapses. Deterministic:
/// no fixed sleeps, fails loudly instead of hanging forever.
async fn wait_for(mut condition: impl FnMut() -> bool, what: &str) {
    let start = Instant::now();
    while !condition() {
        assert!(
            start.elapsed() < POLL_TIMEOUT,
            "timed out waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn find_session(server: &Server, session_id: u64) -> Option<bondnet_server::SessionSnapshot> {
    server
        .sessions()
        .into_iter()
        .find(|s| s.session_id == session_id)
}

/// Test 1 — the server binds an ephemeral localhost port and runs.
#[tokio::test]
async fn server_binds_and_runs() {
    let running = start_server().await;
    assert!(running.addr.port() != 0);
    running.stop().await;
}

/// Test 2 — one valid packet: valid_packets == 1, malformed == 0.
#[tokio::test]
async fn valid_packet_is_counted() {
    let running = start_server().await;
    let tx = sender(running.addr).await;
    let bytes = encode_packet(1, 1, 42, PacketType::Data, vec![0u8; 1200]);
    tx.send(&bytes).await.unwrap();

    wait_for(
        || running.server.stats().valid_packets == 1,
        "valid_packets == 1",
    )
    .await;
    let stats = running.server.stats();
    assert_eq!(stats.datagrams_received, 1);
    assert_eq!(stats.malformed_packets, 0);
    assert_eq!(stats.bytes_received, bytes.len() as u64);
    running.stop().await;
}

/// Test 3 — session 123 / path 7 shows up in the registry.
#[tokio::test]
async fn session_and_path_are_registered() {
    let running = start_server().await;
    let tx = sender(running.addr).await;
    tx.send(&encode_packet(123, 7, 1, PacketType::Data, vec![]))
        .await
        .unwrap();

    wait_for(
        || find_session(&running.server, 123).is_some(),
        "session 123 registered",
    )
    .await;
    let session = find_session(&running.server, 123).unwrap();
    assert_eq!(session.packets_received, 1);
    assert_eq!(session.paths.len(), 1);
    let path = &session.paths[0];
    assert_eq!(path.path_id, 7);
    assert_eq!(path.packets_received, 1);
    assert_eq!(path.last_sequence, 1);
    running.stop().await;
}

/// Test 4 — one session observed over two paths.
#[tokio::test]
async fn multiple_paths_share_one_session() {
    let running = start_server().await;
    let tx = sender(running.addr).await;
    for path_id in [1u16, 2] {
        tx.send(&encode_packet(123, path_id, 1, PacketType::Data, vec![]))
            .await
            .unwrap();
    }

    wait_for(
        || {
            find_session(&running.server, 123)
                .map(|s| s.paths.len() == 2)
                .unwrap_or(false)
        },
        "session 123 has 2 paths",
    )
    .await;
    let sessions = running.server.sessions();
    assert_eq!(sessions.len(), 1);
    running.stop().await;
}

/// Test 5 — two sessions are tracked independently.
#[tokio::test]
async fn multiple_sessions_tracked_independently() {
    let running = start_server().await;
    let tx = sender(running.addr).await;
    for session_id in [100u64, 200] {
        tx.send(&encode_packet(
            session_id,
            1,
            9,
            PacketType::PathHello,
            vec![],
        ))
        .await
        .unwrap();
    }

    wait_for(
        || running.server.sessions().len() == 2,
        "2 sessions registered",
    )
    .await;
    let s100 = find_session(&running.server, 100).unwrap();
    let s200 = find_session(&running.server, 200).unwrap();
    assert_eq!(s100.paths[0].last_sequence, 9);
    assert_eq!(s200.paths[0].last_sequence, 9);
    running.stop().await;
}

/// Test 6 — random bytes are malformed, not fatal.
#[tokio::test]
async fn malformed_packet_is_rejected_safely() {
    let running = start_server().await;
    let tx = sender(running.addr).await;
    tx.send(&[0x00, 0x01, 0x02, 0x03]).await.unwrap();

    wait_for(
        || running.server.stats().malformed_packets == 1,
        "malformed_packets == 1",
    )
    .await;
    assert_eq!(running.server.stats().valid_packets, 0);
    running.stop().await;
}

/// Test 7 — fewer than HEADER_LEN bytes are rejected safely.
#[tokio::test]
async fn truncated_datagram_is_rejected_safely() {
    let running = start_server().await;
    let tx = sender(running.addr).await;
    tx.send(&[0x42, 0x4E, 0x01]).await.unwrap();

    wait_for(
        || running.server.stats().malformed_packets == 1,
        "malformed_packets == 1",
    )
    .await;
    running.stop().await;
}

/// Test 8 — the largest payload a real UDP datagram can carry is accepted.
///
/// The protocol allows 65535-byte payloads, but no UDP datagram can exceed
/// 65535 bytes total (max UDP payload 65507), so the wire-maximum payload
/// is 65507 - 36 = 65471 bytes. The protocol-level 65535 boundary is
/// already covered by bondnet-protocol's own tests.
#[tokio::test]
async fn maximum_payload_is_accepted() {
    /// Largest payload that fits in a single UDP datagram: max UDP payload
    /// (65507) minus the BondNet header.
    const MAX_UDP_PAYLOAD: usize = 65507 - HEADER_LEN;
    let running = start_server().await;
    let tx = sender(running.addr).await;
    let payload = vec![0xABu8; MAX_UDP_PAYLOAD];
    let bytes = encode_packet(5, 5, 5, PacketType::Data, payload);
    tx.send(&bytes).await.unwrap();

    wait_for(
        || running.server.stats().valid_packets == 1,
        "valid_packets == 1",
    )
    .await;
    assert_eq!(running.server.stats().malformed_packets, 0);
    assert_eq!(running.server.stats().bytes_received, bytes.len() as u64);
    running.stop().await;
}

/// Test 9 — every defined packet type is accepted.
#[tokio::test]
async fn all_packet_types_are_accepted() {
    let running = start_server().await;
    let tx = sender(running.addr).await;
    for packet_type in PacketType::all() {
        let bytes = encode_packet(9, 1, 1, packet_type, vec![]);
        tx.send(&bytes).await.unwrap();
    }

    wait_for(
        || running.server.stats().valid_packets == 6,
        "valid_packets == 6",
    )
    .await;
    assert_eq!(running.server.stats().malformed_packets, 0);
    running.stop().await;
}

/// Test 10 — malformed traffic does not kill the server: garbage first,
/// then a valid packet, and both counters move.
#[tokio::test]
async fn server_survives_malformed_traffic() {
    let running = start_server().await;
    let tx = sender(running.addr).await;
    for _ in 0..3 {
        tx.send(&[0xDE, 0xAD, 0xBE, 0xEF]).await.unwrap();
    }
    tx.send(&encode_packet(
        77,
        3,
        3,
        PacketType::Data,
        b"hello".to_vec(),
    ))
    .await
    .unwrap();

    wait_for(
        || {
            let s = running.server.stats();
            s.malformed_packets == 3 && s.valid_packets == 1
        },
        "malformed == 3 and valid == 1",
    )
    .await;
    assert_eq!(running.server.stats().datagrams_received, 4);
    let session = find_session(&running.server, 77).unwrap();
    assert_eq!(session.paths[0].path_id, 3);
    running.stop().await;
}

/// Test 11 — shutdown signal stops the receive loop cleanly.
#[tokio::test]
async fn graceful_shutdown_stops_server() {
    let running = start_server().await;
    running.stop().await;
    // stop() awaits the task and asserts Ok(()): reaching here means the
    // server printed "shutdown requested" / "server stopped" and exited.
}

/// Test 12 — Day 9: Data packets increment the data counters; a
/// non-Data packet does not. Payload byte counts exclude the header.
#[tokio::test]
async fn data_packets_are_counted() {
    let running = start_server().await;
    let tx = sender(running.addr).await;
    let payloads = [vec![0x11u8; 64], vec![0x22u8; 1200], vec![0x33u8; 1400]];
    let mut total: u64 = 0;
    for (i, payload) in payloads.iter().enumerate() {
        total += payload.len() as u64;
        tx.send(&encode_packet(
            1001,
            1,
            10 + i as u64,
            PacketType::Data,
            payload.clone(),
        ))
        .await
        .unwrap();
    }
    tx.send(&encode_packet(1001, 1, 99, PacketType::PathHello, vec![]))
        .await
        .unwrap();

    wait_for(
        || running.server.stats().data_packets == 3,
        "data_packets == 3",
    )
    .await;
    let stats = running.server.stats();
    assert_eq!(stats.data_bytes, total);
    assert_eq!(stats.valid_packets, 4);
    assert_eq!(stats.malformed_packets, 0);
    let session = find_session(&running.server, 1001).unwrap();
    assert_eq!(session.paths[0].last_sequence, 99);
    running.stop().await;
}
