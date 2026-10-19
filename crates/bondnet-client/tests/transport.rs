//! Day 7 transport tests: real UDP sockets on localhost.
//!
//! Binding `127.0.0.1:0` exercises the exact same explicit-bind code path
//! the physical interface will use; only the address differs.

use bondnet_client::{TransportError, UdpPath, UdpPathConfig};
use bondnet_protocol::PacketType;
use tokio::net::UdpSocket;

fn config(path_id: u16, session_id: u64, remote: std::net::SocketAddr) -> UdpPathConfig {
    UdpPathConfig {
        path_id,
        session_id,
        local_addr: "127.0.0.1:0".parse().unwrap(),
        remote_addr: remote,
    }
}

async fn dummy_remote() -> (UdpSocket, std::net::SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    (socket, addr)
}

/// Test 1 — the socket binds the explicitly configured local address.
#[tokio::test]
async fn binds_explicit_local_address() {
    let (_remote, remote_addr) = dummy_remote().await;
    let path = UdpPath::bind(config(1, 1001, remote_addr)).await.unwrap();
    let local = path.local_addr().unwrap();
    assert_eq!(local.ip().to_string(), "127.0.0.1");
    assert_ne!(local.port(), 0, "ephemeral port must be allocated");
}

/// Test 2 — path ID from configuration lands in the packet header.
#[tokio::test]
async fn path_id_is_preserved() {
    let (_remote, remote_addr) = dummy_remote().await;
    let path = UdpPath::bind(config(7, 1001, remote_addr)).await.unwrap();
    assert_eq!(path.path_id(), 7);
    let packet = path.next_packet(PacketType::Data, vec![], 42);
    assert_eq!(packet.header.path_id, 7);
}

/// Test 3 — session ID from configuration lands in the packet header.
#[tokio::test]
async fn session_id_is_preserved() {
    let (_remote, remote_addr) = dummy_remote().await;
    let path = UdpPath::bind(config(1, 1234, remote_addr)).await.unwrap();
    assert_eq!(path.session_id(), 1234);
    let packet = path.next_packet(PacketType::Data, vec![], 42);
    assert_eq!(packet.header.session_id, 1234);
}

/// Test 4 — caller-supplied sequence lands in the packet header.
///
/// Day 15: the sequence is the session-wide logical order, allocated by
/// the data plane — the path only carries it.
#[tokio::test]
async fn sequence_is_caller_supplied() {
    let (_remote, remote_addr) = dummy_remote().await;
    let path = UdpPath::bind(config(1, 1001, remote_addr)).await.unwrap();
    let packet = path.next_packet(PacketType::Data, vec![], 999);
    assert_eq!(packet.header.sequence, 999);
    let packet2 = path.next_packet(PacketType::Data, vec![], 1000);
    assert_eq!(packet2.header.sequence, 1000);
}

/// Test 5 — a packet sent through the transport arrives intact.
#[tokio::test]
async fn localhost_send_receive_round_trip() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let path = UdpPath::bind(config(3, 5555, receiver_addr)).await.unwrap();

    let payload = b"day7-round-trip".to_vec();
    let sent_seq = path
        .send_new(PacketType::Data, payload.clone(), 77)
        .await
        .unwrap();

    let mut buf = vec![0u8; 65535];
    let (len, _) = receiver.recv_from(&mut buf).await.unwrap();
    let received = bondnet_protocol::Packet::decode(&buf[..len]).unwrap();

    assert_eq!(received.header.session_id, 5555);
    assert_eq!(received.header.path_id, 3);
    assert_eq!(received.header.sequence, sent_seq);
    assert_eq!(received.header.packet_type, PacketType::Data);
    assert_eq!(received.payload, payload);

    let stats = path.stats();
    assert_eq!(stats.packets_sent, 1);
    assert_eq!(stats.bytes_sent, len as u64);
    assert_eq!(stats.last_sequence_sent, Some(sent_seq));
}

/// Test 6 — two logical paths carry caller-supplied sequences.
///
/// Day 15: sequences are session-wide, not per-path. Both paths carry
/// whatever sequence the data plane allocates.
#[tokio::test]
async fn multiple_logical_paths_carry_session_sequences() {
    let (_remote, remote_addr) = dummy_remote().await;
    let path1 = UdpPath::bind(config(1, 1001, remote_addr)).await.unwrap();
    let path2 = UdpPath::bind(config(2, 1001, remote_addr)).await.unwrap();

    let p1 = path1.next_packet(PacketType::Data, vec![], 5);
    let p2 = path2.next_packet(PacketType::Data, vec![], 6);
    assert_eq!((p1.header.path_id, p1.header.sequence), (1, 5));
    assert_eq!((p2.header.path_id, p2.header.sequence), (2, 6));
}

/// Test 7 — malformed datagrams fail decode but leave the path usable.
#[tokio::test]
async fn malformed_receive_does_not_kill_path() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let path = UdpPath::bind(config(1, 1001, receiver_addr)).await.unwrap();

    // Aim garbage at the path's own local socket via the receiver socket:
    // connect the raw socket back to the path and send junk.
    let path_local = path.local_addr().unwrap();
    receiver.connect(path_local).await.unwrap();
    receiver.send(b"\x00\x01\x02\x03junk").await.unwrap();

    let err = path.recv_packet().await.unwrap_err();
    assert!(
        matches!(err, TransportError::DecodeFailed(_)),
        "expected DecodeFailed, got {err:?}"
    );

    // Path still works: a valid packet round-trips afterwards.
    let seq = path
        .send_new(PacketType::PathHello, vec![], 100)
        .await
        .unwrap();
    assert_eq!(seq, 100);
    let stats = path.stats();
    assert_eq!(stats.packets_sent, 1);
    assert_eq!(stats.packets_received, 0);
}
