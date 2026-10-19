//! Day 9 integration tests: `DataPlane` → real localhost UDP → decode.
//!
//! Every test sends through the actual `UdpPath` socket and decodes what
//! arrives, proving the exact bytes the data plane wrapped are the bytes
//! the "VPS side" recovers. No sleeps: receives use a hard timeout.

use std::time::Duration;

use bondnet_client::data_plane::{DataPlane, DataPlaneError, MAX_WINTUN_PACKET_LEN};
use bondnet_client::synthetic;
use bondnet_client::{UdpPath, UdpPathConfig};
use bondnet_protocol::{Packet, PacketType};

const RECV_TIMEOUT: Duration = Duration::from_secs(5);

/// A data plane sending to `rx`, plus the receiving socket itself.
/// Session 1001, path 1 — the Day 9 development values from the brief.
/// Day 15: the sequence is session-wide, always starting at 1.
async fn plane_and_receiver() -> (DataPlane, tokio::net::UdpSocket) {
    let rx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let rx_addr = rx.local_addr().unwrap();
    let config = UdpPathConfig {
        path_id: 1,
        session_id: 1001,
        local_addr: "127.0.0.1:0".parse().unwrap(),
        remote_addr: rx_addr,
    };
    let path = std::sync::Arc::new(UdpPath::bind(config).await.unwrap());
    (DataPlane::new(path), rx)
}

/// Receive one datagram from `rx` and decode it as a BondNet packet.
async fn recv_packet(rx: &tokio::net::UdpSocket) -> Packet {
    let mut buf = vec![0u8; 65535];
    let len = tokio::time::timeout(RECV_TIMEOUT, rx.recv(&mut buf))
        .await
        .expect("timed out waiting for datagram")
        .unwrap();
    Packet::decode(&buf[..len]).expect("datagram must decode")
}

/// Test 1 — Wintun bytes become the Data payload unchanged, with the
/// configured session/path/sequence stamped on the envelope.
#[tokio::test]
async fn wintun_bytes_become_data_payload_unchanged() {
    let (plane, rx) = plane_and_receiver().await;
    // Looks like the start of a real IPv4 header; the data plane must
    // not care — it transports bytes, not IP semantics.
    let inner: Vec<u8> = (0..64u8)
        .map(|b| b.wrapping_mul(7).wrapping_add(0x45))
        .collect();

    let seq = plane.send_wintun_packet(&inner).await.unwrap();
    assert_eq!(seq, 1, "Day 15: session-wide sequence starts at 1");

    let packet = recv_packet(&rx).await;
    assert_eq!(packet.header.packet_type, PacketType::Data);
    assert_eq!(packet.payload, inner, "payload must be byte-exact");
    assert_eq!(packet.header.session_id, 1001);
    assert_eq!(packet.header.path_id, 1);
    assert_eq!(
        packet.header.sequence, 1,
        "Day 15: session-wide sequence starts at 1"
    );
}

/// Test 2 — encode/decode round trip preserves the payload exactly.
#[tokio::test]
async fn encode_decode_round_trip_preserves_payload() {
    let inner = synthetic::ipv4_udp_test_packet(&vec![0xABu8; 1472]);
    assert_eq!(inner.len(), 1500);
    let (plane, rx) = plane_and_receiver().await;

    plane.send_wintun_packet(&inner).await.unwrap();
    let packet = recv_packet(&rx).await;
    let re_encoded = packet.encode().unwrap();
    let re_decoded = Packet::decode(&re_encoded).unwrap();
    assert_eq!(re_decoded.payload, inner);
}

/// Test 3 — payloads from 64 to 1500 bytes arrive byte-exact.
#[tokio::test]
async fn payload_sizes_preserved() {
    let (plane, rx) = plane_and_receiver().await;
    for (i, size) in [64usize, 512, 1200, 1400, 1500].iter().enumerate() {
        let payload = vec![(i + 1) as u8; size - 28];
        let inner = synthetic::ipv4_udp_test_packet(&payload);
        assert_eq!(inner.len(), *size);

        let seq = plane.send_wintun_packet(&inner).await.unwrap();
        let packet = recv_packet(&rx).await;
        // Day 15: session-wide sequences start at 1.
        assert_eq!(packet.header.sequence, 1 + i as u64);
        assert_eq!(seq, 1 + i as u64);
        assert_eq!(packet.payload, inner, "size {size} must be byte-exact");
    }
}

/// Test 4 — three packets get consecutive tunnel sequence numbers.
#[tokio::test]
async fn sequence_increases_monotonically() {
    let (plane, rx) = plane_and_receiver().await;
    let mut seqs = Vec::new();
    for _ in 0..3 {
        let inner = synthetic::ipv4_udp_test_packet(b"seq-test");
        seqs.push(plane.send_wintun_packet(&inner).await.unwrap());
        let packet = recv_packet(&rx).await;
        assert_eq!(packet.header.sequence, *seqs.last().unwrap());
    }
    // Day 15: session-wide sequences start at 1 and increment by 1.
    assert_eq!(seqs, [1, 2, 3]);
}

/// Test 5 — every outgoing packet carries path_id = 1, session_id = 1001.
#[tokio::test]
async fn path_and_session_metadata_preserved() {
    let (plane, rx) = plane_and_receiver().await;
    for _ in 0..3 {
        let inner = synthetic::ipv4_udp_test_packet(b"meta");
        plane.send_wintun_packet(&inner).await.unwrap();
        let packet = recv_packet(&rx).await;
        assert_eq!(packet.header.path_id, 1);
        assert_eq!(packet.header.session_id, 1001);
        assert_eq!(packet.header.packet_type, PacketType::Data);
    }
}

/// Test 6 — a 1501-byte inner packet is rejected, counted, and never sent.
#[tokio::test]
async fn oversized_packet_rejected_and_counted() {
    let (plane, _rx) = plane_and_receiver().await;
    let big = vec![0u8; MAX_WINTUN_PACKET_LEN + 1];

    let error = plane.send_wintun_packet(&big).await.unwrap_err();
    assert!(
        matches!(
            error,
            DataPlaneError::PacketTooLarge { len, max }
            if len == MAX_WINTUN_PACKET_LEN + 1 && max == MAX_WINTUN_PACKET_LEN
        ),
        "unexpected error: {error}"
    );
    let m = plane.metrics_snapshot();
    assert_eq!(m.oversized_dropped, 1);
    assert_eq!(m.tunnel_packets_sent, 0);
}

/// Test 6b — the budget is configurable; a smaller budget rejects sooner.
#[tokio::test]
async fn custom_budget_rejects_sooner() {
    let rx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let rx_addr = rx.local_addr().unwrap();
    let config = UdpPathConfig {
        path_id: 1,
        session_id: 1001,
        local_addr: "127.0.0.1:0".parse().unwrap(),
        remote_addr: rx_addr,
    };
    let plane = DataPlane::with_max_wintun_len(
        std::sync::Arc::new(UdpPath::bind(config).await.unwrap()),
        100,
    );
    assert_eq!(plane.max_wintun_len(), 100);

    let ok_packet = vec![0u8; 100];
    assert!(plane.send_wintun_packet(&ok_packet).await.is_ok());
    let big_packet = vec![0u8; 101];
    assert!(matches!(
        plane.send_wintun_packet(&big_packet).await,
        Err(DataPlaneError::PacketTooLarge { len: 101, max: 100 })
    ));
}

/// Test 7 — an empty "packet" is rejected, counted, and never sent.
#[tokio::test]
async fn empty_packet_rejected() {
    let (plane, _rx) = plane_and_receiver().await;
    assert!(matches!(
        plane.send_wintun_packet(&[]).await,
        Err(DataPlaneError::EmptyPacket)
    ));
    let m = plane.metrics_snapshot();
    assert_eq!(m.invalid_dropped, 1);
    assert_eq!(m.tunnel_packets_sent, 0);
}

/// Test 8 — the synthetic fixture really looks like an IPv4/UDP packet.
#[tokio::test]
async fn synthetic_fixture_is_valid_ipv4() {
    let packet = synthetic::ipv4_udp_test_packet(b"hello");
    assert_eq!(packet[0] >> 4, 4, "IP version nibble must be 4");
    assert_eq!(packet[9], 17, "protocol must be UDP");
    let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    assert_eq!(total, packet.len());
    assert!(synthetic::ipv4_checksum_valid(&packet));
}

/// Test 9 — a full send updates the tunnel counters exactly.
#[tokio::test]
async fn metrics_count_sends() {
    let (plane, rx) = plane_and_receiver().await;
    let payload = vec![9u8; 100];
    let inner = synthetic::ipv4_udp_test_packet(&payload);
    plane.send_wintun_packet(&inner).await.unwrap();
    recv_packet(&rx).await;

    let m = plane.metrics_snapshot();
    assert_eq!(m.tunnel_packets_sent, 1);
    assert_eq!(m.tunnel_bytes_sent, (36 + inner.len()) as u64);
    assert_eq!(m.send_errors, 0);
}
