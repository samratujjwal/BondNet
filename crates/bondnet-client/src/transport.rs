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

use bondnet_protocol::{HEADER_LEN, MAGIC, PROTOCOL_VERSION, Packet, PacketHeader, PacketType};
use tokio::net::UdpSocket;

use crate::config::UdpPathConfig;
use crate::error::TransportError;

/// Construct the 36-byte header encoding for use as AAD.
///
/// This replicates the header serialization from `Packet::encode`,
/// with the given `payload_len` (used for the ciphertext length when
/// encrypting).
fn header_aad(header: &PacketHeader, payload_len: usize) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0..2].copy_from_slice(&MAGIC);
    out[2] = header.version;
    out[3] = header.flags;
    out[4..6].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
    out[6..14].copy_from_slice(&header.session_id.to_be_bytes());
    out[14..22].copy_from_slice(&header.sequence.to_be_bytes());
    out[22..24].copy_from_slice(&header.path_id.to_be_bytes());
    out[24] = header.packet_type.as_u8();
    out[25] = 0; // reserved
    out[26..34].copy_from_slice(&header.timestamp.to_be_bytes());
    out[34..36].copy_from_slice(&(payload_len as u16).to_be_bytes());
    out
}

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
    stats: PathStats,
    /// Day 18: optional secure session. When set, DATA payloads are
    /// encrypted with authenticated encryption before sending.
    secure_session: std::sync::Mutex<Option<std::sync::Arc<bondnet_crypto::SecureSession>>>,
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
            socket,
            config,
            stats: PathStats::default(),
            secure_session: std::sync::Mutex::new(None),
        })
    }

    /// Day 18: attach a secure session for authenticated encryption.
    /// When attached, DATA packet payloads are encrypted before sending.
    pub fn set_secure_session(&self, session: std::sync::Arc<bondnet_crypto::SecureSession>) {
        *self.secure_session.lock().expect("secure lock poisoned") = Some(session);
    }

    /// Day 20: the session salt of the attached secure session, if any.
    /// The caller sends this in the PathHello payload (32 bytes) so the
    /// server derives matching keys.
    pub fn secure_salt(&self) -> Option<[u8; 32]> {
        self.secure_session
            .lock()
            .expect("secure lock poisoned")
            .as_ref()
            .map(|s| *s.session_salt())
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

    /// Build an outbound packet: stamps the configured session and path
    /// IDs, the caller-supplied logical sequence number, and the current
    /// Unix time in milliseconds.
    ///
    /// Day 15: the sequence is the session-wide logical order (allocated
    /// by the data plane before path selection), NOT a per-path counter.
    /// The path only carries the sequence; it never allocates it.
    pub fn next_packet(&self, packet_type: PacketType, payload: Vec<u8>, sequence: u64) -> Packet {
        // Day 18: if a secure session is set and this is a DATA packet,
        // encrypt the payload with the header as AAD.
        let secure = if packet_type == PacketType::Data {
            self.secure_session
                .lock()
                .expect("secure lock poisoned")
                .clone()
        } else {
            None
        };

        let header = PacketHeader {
            version: PROTOCOL_VERSION,
            flags: 0,
            session_id: self.config.session_id,
            sequence,
            path_id: self.config.path_id,
            packet_type,
            timestamp: unix_millis(),
        };

        let payload = if let Some(session) = secure {
            // Ciphertext is plaintext + 16-byte tag.
            let ciphertext_len = payload.len() + bondnet_crypto::TAG_SIZE;
            // Build AAD from the header with the ciphertext length.
            let aad = header_aad(&header, ciphertext_len);
            // Day 19: use KeyDomain::UploadData with sequence as the nonce
            // counter. The sequence is unique per (session, direction),
            // so the nonce is unique. The server reconstructs the nonce
            // from the header's sequence field.
            session
                .encrypt_with_counter(
                    bondnet_crypto::KeyDomain::UploadData,
                    sequence,
                    &aad,
                    &payload,
                )
                .expect("encryption is infallible with valid key/nonce")
        } else {
            payload
        };

        Packet { header, payload }
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

    /// Build a packet with the given logical sequence and send it.
    /// Returns the sequence number used.
    pub async fn send_new(
        &self,
        packet_type: PacketType,
        payload: Vec<u8>,
        sequence: u64,
    ) -> Result<u64, TransportError> {
        let packet = self.next_packet(packet_type, payload, sequence);
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
