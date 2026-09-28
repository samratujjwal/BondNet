//! Day 7 client transport: one physical UDP path to the VPS.
//!
//! The socket is bound to the configured local IPv4 address — the address
//! owned by the physical interface we want traffic to leave through — and
//! then connected to the VPS endpoint. Binding selects the local address;
//! the OS routing table still decides the actual egress interface, which
//! for a local address owned by one adapter is that adapter.
//!
//! Connected UDP does NOT make UDP TCP-like: it only sets a default peer
//! so `send`/`recv` need no per-datagram address, and the OS drops
//! datagrams arriving from any other source.

use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use bondnet_protocol::{PROTOCOL_VERSION, Packet, PacketHeader, PacketType};
use tokio::net::UdpSocket;

use crate::config::UdpPathConfig;
use crate::error::TransportError;

/// Plain-data copy of per-path counters, for tests and future inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PathStatsSnapshot {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_received: u64,
    pub bytes_received: u64,
    /// Sequence number stamped on the most recently sent packet, if any.
    pub last_sequence_sent: Option<u64>,
}

#[derive(Debug, Default)]
struct PathStats {
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    packets_received: AtomicU64,
    bytes_received: AtomicU64,
    last_sequence_sent: Mutex<Option<u64>>,
}

/// One physical UDP path: a socket bound to an explicit local IPv4 address,
/// connected to the VPS, stamping BondNet tunnel sequence numbers.
pub struct UdpPath {
    socket: UdpSocket,
    config: UdpPathConfig,
    next_sequence: AtomicU64,
    stats: PathStats,
}

impl UdpPath {
    /// Bind the configured local address, then connect to the remote VPS
    /// endpoint. The bind is what pins this path to the physical
    /// interface owning `local_addr`; `connect` only fixes the peer.
    pub async fn bind(config: UdpPathConfig) -> Result<Self, TransportError> {
        if !config.local_addr.ip().is_ipv4() {
            return Err(TransportError::InvalidLocalAddress(
                config.local_addr.to_string(),
            ));
        }
        let socket = UdpSocket::bind(config.local_addr)
            .await
            .map_err(TransportError::BindFailed)?;
        socket
            .connect(config.remote_addr)
            .await
            .map_err(TransportError::ConnectFailed)?;
        Ok(Self {
            next_sequence: AtomicU64::new(config.initial_sequence),
            socket,
            config,
            stats: PathStats::default(),
        })
    }

    /// The actual bound local address (ephemeral port resolved).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// The configured VPS endpoint.
    pub fn remote_addr(&self) -> SocketAddr {
        self.config.remote_addr
    }

    /// The local address from configuration (before ephemeral port
    /// allocation). Compare with [`local_addr`](Self::local_addr) to prove
    /// the socket owns the intended physical-interface address.
    pub fn configured_local_addr(&self) -> SocketAddr {
        self.config.local_addr
    }

    /// BondNet logical path identifier from configuration.
    pub fn path_id(&self) -> u16 {
        self.config.path_id
    }

    /// BondNet tunnel session identifier from configuration.
    pub fn session_id(&self) -> u64 {
        self.config.session_id
    }

    /// Current counters.
    pub fn stats(&self) -> PathStatsSnapshot {
        PathStatsSnapshot {
            packets_sent: self.stats.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            packets_received: self.stats.packets_received.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            last_sequence_sent: *self
                .stats
                .last_sequence_sent
                .lock()
                .expect("stats lock poisoned"),
        }
    }

    /// Build the next outbound packet: stamps the configured session and
    /// path IDs, the next monotonic tunnel sequence number, and the
    /// current Unix time in milliseconds. No wrap-around handling yet.
    pub fn next_packet(&self, packet_type: PacketType, payload: Vec<u8>) -> Packet {
        let sequence = self.next_sequence.fetch_add(1, Ordering::SeqCst);
        Packet {
            header: PacketHeader {
                version: PROTOCOL_VERSION,
                flags: 0,
                session_id: self.config.session_id,
                sequence,
                path_id: self.config.path_id,
                packet_type,
                timestamp: unix_millis(),
            },
            payload,
        }
    }

    /// Encode `packet` and send it to the VPS. Updates send telemetry.
    /// Returns the number of bytes handed to the OS.
    pub async fn send_packet(&self, packet: &Packet) -> Result<usize, TransportError> {
        let bytes = packet.encode().map_err(TransportError::EncodeFailed)?;
        let sent = self
            .socket
            .send(&bytes)
            .await
            .map_err(TransportError::SendFailed)?;
        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(sent as u64, Ordering::Relaxed);
        *self
            .stats
            .last_sequence_sent
            .lock()
            .expect("stats lock poisoned") = Some(packet.header.sequence);
        Ok(sent)
    }

    /// Build the next packet and send it. Returns the sequence number used.
    pub async fn send_new(
        &self,
        packet_type: PacketType,
        payload: Vec<u8>,
    ) -> Result<u64, TransportError> {
        let packet = self.next_packet(packet_type, payload);
        let sequence = packet.header.sequence;
        self.send_packet(&packet).await?;
        Ok(sequence)
    }

    /// Receive one datagram from the connected peer and decode it.
    /// A malformed datagram yields `DecodeFailed` and leaves the
    /// transport fully usable — the error is per-datagram, not fatal.
    pub async fn recv_packet(&self) -> Result<Packet, TransportError> {
        // 64 KiB covers any UDP payload the peer can legally send.
        let mut buf = vec![0u8; 65535];
        let len = self
            .socket
            .recv(&mut buf)
            .await
            .map_err(TransportError::ReceiveFailed)?;
        let packet = Packet::decode(&buf[..len]).map_err(TransportError::DecodeFailed)?;
        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_received
            .fetch_add(len as u64, Ordering::Relaxed);
        Ok(packet)
    }
}

/// Current Unix time in milliseconds. The protocol transports this value;
/// it never reads a clock itself.
fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
