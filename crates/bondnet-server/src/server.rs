//! Day 6 UDP receive loop: bind, receive, decode, track, count.
//!
//! The server is intentionally receive/validate/telemetry only:
//!
//! * every datagram goes through `bondnet_protocol::Packet::decode` — the
//!   protocol crate is the single wire-format source of truth, never
//!   duplicated here;
//! * malformed datagrams increment a counter and are logged concisely; the
//!   server keeps running;
//! * observed `(session_id, path_id)` pairs are recorded in an in-memory
//!   registry (no authentication, no session management yet);
//! * no ACK is ever generated — the ACK payload contract does not exist
//!   yet, and inventing one would be fake protocol.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bondnet_protocol::{HEADER_LEN, MAX_PAYLOAD_LEN, Packet, PacketType};
use tokio::net::UdpSocket;

use crate::config::ServerConfig;

/// Receive buffer size: header + maximum protocol payload.
///
/// 36 + 65535 = 65571 bytes, which is larger than the biggest possible UDP
/// datagram (65535 bytes), so `recv_from` can never silently truncate a
/// datagram into this buffer. Anything that cannot be a valid packet is
/// rejected by `Packet::decode` instead of by unsafe truncation.
pub const RECV_BUF_LEN: usize = HEADER_LEN + MAX_PAYLOAD_LEN;

/// Server-wide counters. Atomics so tests (and future admin endpoints) can
/// read them without stopping the receive loop.
#[derive(Debug, Default)]
pub struct ServerStats {
    /// Every UDP datagram received, valid or not.
    pub datagrams_received: AtomicU64,
    /// Datagrams that decoded into a valid BondNet packet.
    pub valid_packets: AtomicU64,
    /// Datagrams that failed `Packet::decode`.
    pub malformed_packets: AtomicU64,
    /// Sum of received datagram lengths in bytes.
    pub bytes_received: AtomicU64,
    /// Day 9: datagrams that decoded as `PacketType::Data`.
    pub data_packets: AtomicU64,
    /// Day 9: sum of `Data` payload lengths in bytes (header excluded).
    pub data_bytes: AtomicU64,
}

/// Plain-data copy of [`ServerStats`] for assertions and logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatsSnapshot {
    pub datagrams_received: u64,
    pub valid_packets: u64,
    pub malformed_packets: u64,
    pub bytes_received: u64,
    /// Day 9: datagrams that decoded as `PacketType::Data`.
    pub data_packets: u64,
    /// Day 9: sum of `Data` payload lengths in bytes (header excluded).
    pub data_bytes: u64,
}

impl ServerStats {
    fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            datagrams_received: self.datagrams_received.load(Ordering::Relaxed),
            valid_packets: self.valid_packets.load(Ordering::Relaxed),
            malformed_packets: self.malformed_packets.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            data_packets: self.data_packets.load(Ordering::Relaxed),
            data_bytes: self.data_bytes.load(Ordering::Relaxed),
        }
    }
}

/// What the server remembers about one observed `(session_id, path_id)`.
///
/// UDP is connectionless: `remote_addr` is simply the latest observed
/// source address, and `last_sequence` is the latest observed BondNet
/// tunnel sequence (observed only — never used to reorder or reject).
#[derive(Debug, Clone)]
struct PathState {
    remote_addr: SocketAddr,
    last_seen: Instant,
    packets_received: u64,
    bytes_received: u64,
    last_sequence: u64,
}

/// What the server remembers about one observed `session_id`.
#[derive(Debug, Clone)]
struct SessionState {
    last_seen: Instant,
    packets_received: u64,
    paths: HashMap<u16, PathState>,
}

/// Plain-data copy of one observed path, for tests and future inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSnapshot {
    pub path_id: u16,
    pub remote_addr: SocketAddr,
    pub packets_received: u64,
    pub bytes_received: u64,
    pub last_sequence: u64,
}

/// Plain-data copy of one observed session, for tests and future inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub session_id: u64,
    pub packets_received: u64,
    pub paths: Vec<PathSnapshot>,
}

/// The Day 6 server: configuration plus shared mutable state.
///
/// Cheap to clone behind `Arc`; the receive loop and the test harness can
/// hold the same instance.
pub struct Server {
    config: ServerConfig,
    stats: Arc<ServerStats>,
    registry: Arc<Mutex<HashMap<u64, SessionState>>>,
}

impl Server {
    /// Create a server from configuration. Does not bind yet; see
    /// [`run`](Self::run) and [`run_on`](Self::run_on).
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            stats: Arc::new(ServerStats::default()),
            registry: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Current counters.
    pub fn stats(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }

    /// Snapshot of every observed session and its paths.
    pub fn sessions(&self) -> Vec<SessionSnapshot> {
        let registry = self.registry.lock().expect("registry lock poisoned");
        registry
            .iter()
            .map(|(&session_id, session)| SessionSnapshot {
                session_id,
                packets_received: session.packets_received,
                paths: session
                    .paths
                    .iter()
                    .map(|(&path_id, path)| PathSnapshot {
                        path_id,
                        remote_addr: path.remote_addr,
                        packets_received: path.packets_received,
                        bytes_received: path.bytes_received,
                        last_sequence: path.last_sequence,
                    })
                    .collect(),
            })
            .collect()
    }

    /// Bind the configured address and run until `shutdown` resolves.
    pub async fn run(&self, shutdown: impl Future<Output = ()> + Send) -> io::Result<()> {
        let socket = UdpSocket::bind(self.config.bind_addr).await?;
        self.run_on(socket, shutdown).await
    }

    /// Run the receive loop on an already-bound socket until `shutdown`
    /// resolves. Tests use this to bind ephemeral ports; production uses
    /// [`run`](Self::run).
    pub async fn run_on(
        &self,
        socket: UdpSocket,
        shutdown: impl Future<Output = ()> + Send,
    ) -> io::Result<()> {
        println!("server listening on {}", socket.local_addr()?);
        // Heap allocation: 64 KiB on the async task's stack would be rude.
        let mut buf = vec![0u8; RECV_BUF_LEN];
        let mut shutdown = Box::pin(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    println!("shutdown requested");
                    break;
                }
                result = socket.recv_from(&mut buf) => {
                    let (len, remote) = result?;
                    self.handle_datagram(&buf[..len], remote);
                }
            }
        }
        println!("server stopped");
        Ok(())
    }

    /// Classify one datagram: count it, decode it, and either record the
    /// packet or record the failure. Never panics on network input.
    fn handle_datagram(&self, datagram: &[u8], remote: SocketAddr) {
        self.stats
            .datagrams_received
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_received
            .fetch_add(datagram.len() as u64, Ordering::Relaxed);

        let packet = match Packet::decode(datagram) {
            Ok(packet) => packet,
            Err(error) => {
                self.stats.malformed_packets.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "WARN malformed datagram remote={remote} len={} error={error}",
                    datagram.len()
                );
                return;
            }
        };

        self.stats.valid_packets.fetch_add(1, Ordering::Relaxed);
        // Day 9: observe Data packets for the tunnel proof. Counting only —
        // the payload is never forwarded anywhere (no NAT, no TUN yet).
        if packet.header.packet_type == PacketType::Data {
            self.stats.data_packets.fetch_add(1, Ordering::Relaxed);
            self.stats
                .data_bytes
                .fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
        }
        self.record_packet(&packet, datagram.len(), remote);

        if self.config.verbose {
            let h = &packet.header;
            if h.packet_type == PacketType::Data {
                // One concise line per Data packet. The fingerprint is a
                // test-only FNV-1a checksum — NOT cryptographic, NOT
                // authentication — so the smoke test can confirm the exact
                // payload arrived without dumping packet bytes to stdout.
                println!(
                    "DATA_RX session={} path={} seq={} payload_len={} fp={:016x} remote={remote}",
                    h.session_id,
                    h.path_id,
                    h.sequence,
                    packet.payload.len(),
                    payload_fingerprint(&packet.payload),
                );
            } else {
                println!(
                    "RX session={} path={} seq={} type={:?} payload={} remote={remote}",
                    h.session_id,
                    h.path_id,
                    h.sequence,
                    h.packet_type,
                    packet.payload.len(),
                );
            }
        }
    }

    /// Insert or update the `(session_id, path_id)` registry entry.
    /// Observation only: no authentication, no reordering, no rejection.
    fn record_packet(&self, packet: &Packet, len: usize, remote: SocketAddr) {
        let h = &packet.header;
        let now = Instant::now();
        let mut registry = self.registry.lock().expect("registry lock poisoned");
        let session = registry
            .entry(h.session_id)
            .or_insert_with(|| SessionState {
                last_seen: now,
                packets_received: 0,
                paths: HashMap::new(),
            });
        session.last_seen = now;
        session.packets_received += 1;
        let path = session.paths.entry(h.path_id).or_insert_with(|| PathState {
            remote_addr: remote,
            last_seen: now,
            packets_received: 0,
            bytes_received: 0,
            last_sequence: h.sequence,
        });
        path.remote_addr = remote;
        path.last_seen = now;
        path.packets_received += 1;
        path.bytes_received += len as u64;
        path.last_sequence = h.sequence;
    }
}

/// Test-only 64-bit FNV-1a checksum of a `Data` payload.
///
/// Used solely so the Day 9 smoke test can confirm byte-exact delivery in
/// logs without dumping packet bytes. This is NOT a cryptographic hash,
/// NOT authentication, and MUST NOT be mistaken for either — crypto
/// integration is a later milestone.
fn payload_fingerprint(bytes: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut hash = FNV_OFFSET;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}
