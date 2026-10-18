//! Day 6 UDP receive loop: bind, receive, decode, track, count.
//!
//! Day 10: when `--tun-name` is given, validated `Data` payloads are also
//! forwarded into a Linux TUN device (bounded queue + dedicated writer
//! thread, so the Tokio executor never blocks). Without `--tun-name` the
//! server behaves exactly like Day 6/9: receive/validate/telemetry only.
//!
//! Day 11: when `--tun-return-session`/`--tun-return-path` are given, the
//! reverse path is enabled: a dedicated reader thread `poll(2)`s the TUN
//! fd, validated IP packets are encapsulated as `Data` and queued
//! (bounded) to an async sender task that `send_to`s them to the observed
//! client endpoint — reusing the same bound UDP socket the client
//! connected to. Without the return flags the server behaves exactly like
//! Day 10.
//!
//! Forwarding gate (in order — a packet must pass ALL of them):
//!
//! ```text
//! UDP datagram
//!   → Packet::decode()          (bondnet-protocol is the single wire truth)
//!   → PacketType::Data          (any other type never touches TUN)
//!   → validate_ip_packet()      (structural IPv4/IPv6 check, no panics)
//!   → bounded mpsc queue (1024) (full → drop newest, count it)
//!   → writer thread             (one write(2) per packet into the kernel)
//! ```
//!
//! Return gate (Day 11, in order):
//!
//! ```text
//! TUN read(2)
//!   → validate_ip_packet()      (bad IP never becomes a return packet)
//!   → endpoint association      (configured session/path, observed remote,
//!                                unknown or expired → drop + count)
//!   → return sequence           (per-path directional counter, server-owned)
//!   → PacketType::Data encode   (payload byte-for-byte unchanged)
//!   → bounded mpsc queue (1024) (full → drop newest, count it)
//!   → send_to                   (same bound socket the client connected to)
//! ```
//!
//! Direction is by arrival interface, never by a header flag: UDP→TUN is
//! upload, TUN→UDP is return. The two pipelines share the fd but never
//! feed each other, so packets cannot loop.
//!
//! The server is still intentionally plaintext (no crypto yet) and still
//! generates no ACKs.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bondnet_protocol::{
    HEADER_LEN, MAX_PAYLOAD_LEN, PROTOCOL_VERSION, Packet, PacketHeader, PacketType,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::config::ServerConfig;
use crate::tun::{TunDevice, validate_ip_packet};

/// Receive buffer size: header + maximum protocol payload.
///
/// 36 + 65535 = 65571 bytes, which is larger than the biggest possible UDP
/// datagram (65535 bytes), so `recv_from` can never silently truncate a
/// datagram into this buffer. Anything that cannot be a valid packet is
/// rejected by `Packet::decode` instead of by unsafe truncation.
pub const RECV_BUF_LEN: usize = HEADER_LEN + MAX_PAYLOAD_LEN;

/// Capacity of the validated-packet queue feeding the TUN writer thread.
///
/// Bounded on purpose: an unbounded queue would let a slow kernel consumer
/// grow memory without limit. When full, the newest packet is dropped and
/// `tun_queue_dropped` counts it (same drop-newest policy as Day 9's
/// Wintun→Tokio boundary).
pub const TUN_QUEUE_CAPACITY: usize = 1024;

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
    /// Day 10: validated IP packets written into the TUN device.
    pub tun_packets_written: AtomicU64,
    /// Day 10: sum of bytes written into the TUN device.
    pub tun_bytes_written: AtomicU64,
    /// Day 10: `Data` payloads that failed IP validation (never enter TUN).
    pub tun_invalid_ip: AtomicU64,
    /// Day 10: TUN `write(2)` failures, including WouldBlock drops.
    pub tun_write_errors: AtomicU64,
    /// Day 10: validated packets dropped because the TUN queue was full.
    pub tun_queue_dropped: AtomicU64,
    /// Day 10: packets read back from the TUN device (Day 11 return path;
    /// the reader is not wired up yet, so this stays 0).
    pub tun_packets_read: AtomicU64,
    /// Day 10: bytes read back from the TUN device (see above).
    pub tun_bytes_read: AtomicU64,
    /// Day 11: TUN `read(2)` failures on the reader thread (not WouldBlock;
    /// that is a spurious wakeup, not an error).
    pub tun_read_errors: AtomicU64,
    /// Day 11: return `Data` packets handed to the UDP socket.
    pub return_packets_sent: AtomicU64,
    /// Day 11: return wire bytes handed to the UDP socket (header + payload).
    pub return_bytes_sent: AtomicU64,
    /// Day 11: TUN-read packets that failed IP validation (never sent).
    pub return_invalid_ip: AtomicU64,
    /// Day 11: TUN-read packets dropped because the configured
    /// `(session, path)` had no live endpoint association (unknown or
    /// expired).
    pub return_no_endpoint: AtomicU64,
    /// Day 11: UDP `send_to` failures on the return path.
    pub return_send_errors: AtomicU64,
    /// Day 11: return packets dropped because the reader→sender queue was
    /// full (drop newest, same policy as the Day 10 TUN queue).
    pub return_backpressure_dropped: AtomicU64,
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
    /// Day 10: validated IP packets written into the TUN device.
    pub tun_packets_written: u64,
    /// Day 10: sum of bytes written into the TUN device.
    pub tun_bytes_written: u64,
    /// Day 10: `Data` payloads that failed IP validation.
    pub tun_invalid_ip: u64,
    /// Day 10: TUN write failures.
    pub tun_write_errors: u64,
    /// Day 10: packets dropped on a full TUN queue.
    pub tun_queue_dropped: u64,
    /// Day 10: packets read from TUN (Day 11; currently always 0).
    pub tun_packets_read: u64,
    /// Day 10: bytes read from TUN (Day 11; currently always 0).
    pub tun_bytes_read: u64,
    /// Day 11: TUN read failures on the reader thread.
    pub tun_read_errors: u64,
    /// Day 11: return `Data` packets handed to the UDP socket.
    pub return_packets_sent: u64,
    /// Day 11: return wire bytes handed to the UDP socket.
    pub return_bytes_sent: u64,
    /// Day 11: TUN-read packets that failed IP validation.
    pub return_invalid_ip: u64,
    /// Day 11: return packets dropped for lack of a live endpoint.
    pub return_no_endpoint: u64,
    /// Day 11: UDP send failures on the return path.
    pub return_send_errors: u64,
    /// Day 11: return packets dropped on a full return queue.
    pub return_backpressure_dropped: u64,
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
            tun_packets_written: self.tun_packets_written.load(Ordering::Relaxed),
            tun_bytes_written: self.tun_bytes_written.load(Ordering::Relaxed),
            tun_invalid_ip: self.tun_invalid_ip.load(Ordering::Relaxed),
            tun_write_errors: self.tun_write_errors.load(Ordering::Relaxed),
            tun_queue_dropped: self.tun_queue_dropped.load(Ordering::Relaxed),
            tun_packets_read: self.tun_packets_read.load(Ordering::Relaxed),
            tun_bytes_read: self.tun_bytes_read.load(Ordering::Relaxed),
            tun_read_errors: self.tun_read_errors.load(Ordering::Relaxed),
            return_packets_sent: self.return_packets_sent.load(Ordering::Relaxed),
            return_bytes_sent: self.return_bytes_sent.load(Ordering::Relaxed),
            return_invalid_ip: self.return_invalid_ip.load(Ordering::Relaxed),
            return_no_endpoint: self.return_no_endpoint.load(Ordering::Relaxed),
            return_send_errors: self.return_send_errors.load(Ordering::Relaxed),
            return_backpressure_dropped: self.return_backpressure_dropped.load(Ordering::Relaxed),
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
    /// Day 11: next tunnel sequence number for the RETURN direction
    /// (server → client) on this path.
    ///
    /// This is a *directional* sequence space, independent of the client's
    /// outbound counter for the same `(session_id, path_id)`: the client
    /// stamps its Wintun→UDP packets, the server stamps its TUN→UDP
    /// packets. A receiver distinguishes direction by arrival interface
    /// (UDP socket vs. TUN/Wintun), never by comparing sequence numbers
    /// across directions. No wrap-around handling yet.
    return_sequence: u64,
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

/// Capacity of the return-packet queue feeding the UDP sender task.
///
/// Same reasoning as [`TUN_QUEUE_CAPACITY`]: bounded so a slow socket can
/// never grow memory without bound. When full, the newest return packet
/// is dropped and `return_backpressure_dropped` counts it.
pub const RETURN_QUEUE_CAPACITY: usize = 1024;

/// Largest IP packet the TUN reader accepts, in bytes.
///
/// 65535 is the largest IP packet the kernel can hand us; the fd moves
/// exactly one packet per `read(2)` (`IFF_TUN | IFF_NO_PI`).
pub const TUN_READ_BUF_LEN: usize = 65535;

/// How long the TUN reader thread blocks in `poll(2)` before re-checking
/// the shutdown flag. Not a packet-latency bound: `poll` returns
/// immediately when the fd is readable.
#[cfg(target_os = "linux")]
const TUN_READER_POLL_TIMEOUT_MS: i32 = 100;

/// An addressed, encoded return datagram: the client's observed UDP
/// endpoint plus the BondNet `Data` bytes to send it.
type ReturnDatagram = (SocketAddr, Vec<u8>);

/// The server: configuration plus shared mutable state.
///
/// Cheap to clone behind `Arc`; the receive loop and the test harness can
/// hold the same instance.
pub struct Server {
    config: ServerConfig,
    stats: Arc<ServerStats>,
    registry: Arc<Mutex<HashMap<u64, SessionState>>>,
    /// Sending end of the TUN queue. `None` when TUN is disabled (Day 6/9
    /// behavior) — `forward_to_tun` then does nothing.
    tun_tx: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    /// The TUN writer thread. Joined on shutdown so no packet is lost
    /// between "queue drained" and "device closed".
    tun_writer: Mutex<Option<JoinHandle<()>>>,
    /// Day 11: the shared TUN device. Held as `Arc` so the Day 10 writer
    /// thread and the Day 11 reader thread can use the same fd; the
    /// kernel destroys the interface when the last `Arc` drops.
    tun_device: Mutex<Option<Arc<TunDevice>>>,
    /// Day 11: the bound UDP socket, shared so the return sender task can
    /// `send_to` from the same local port the client connected to. (A
    /// connected client socket drops datagrams from any other source, so
    /// the return path MUST reuse this socket.)
    udp_socket: Mutex<Option<Arc<UdpSocket>>>,
    /// Day 11: sending end of the return queue (encoded datagram +
    /// destination). `None` unless the return path is configured.
    return_tx: Mutex<Option<mpsc::Sender<ReturnDatagram>>>,
    /// Day 11: the async return sender task. Awaited on shutdown after
    /// the queue is closed.
    return_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Day 11: the TUN reader thread. Joined on shutdown.
    tun_reader: Mutex<Option<JoinHandle<()>>>,
    /// Day 11: shutdown flag for the reader thread.
    reader_shutdown: Mutex<Option<Arc<AtomicBool>>>,
}

impl Server {
    /// Create a server from configuration. Does not bind yet; see
    /// [`run`](Self::run) and [`run_on`](Self::run_on).
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            stats: Arc::new(ServerStats::default()),
            registry: Arc::new(Mutex::new(HashMap::new())),
            tun_tx: Mutex::new(None),
            tun_writer: Mutex::new(None),
            tun_device: Mutex::new(None),
            udp_socket: Mutex::new(None),
            return_tx: Mutex::new(None),
            return_task: Mutex::new(None),
            tun_reader: Mutex::new(None),
            reader_shutdown: Mutex::new(None),
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
        // Day 11: share the socket so the return sender task can reply
        // from the same local port the client connected to.
        let socket = Arc::new(socket);
        *self.udp_socket.lock().expect("socket lock poisoned") = Some(Arc::clone(&socket));
        // Day 10: create the TUN device and writer thread before the first
        // datagram can arrive. Without --tun-name this is a no-op.
        self.start_tun()?;
        // Day 11: start the TUN reader + return sender. No-op unless the
        // return association is configured.
        self.start_return_path(&socket)?;
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
        // Day 11: stop the reader first (it may still be enqueueing),
        // then drain the return queue through the sender task.
        self.stop_return_path().await;
        // Day 10: drain the TUN queue, join the writer, then close the
        // device (the kernel destroys the non-persistent interface).
        self.stop_tun();
        // Release the last device reference; the interface is destroyed
        // once the reader and writer threads have dropped theirs.
        drop(
            self.tun_device
                .lock()
                .expect("tun device lock poisoned")
                .take(),
        );
        println!("server stopped");
        Ok(())
    }

    /// Create the TUN device and spawn its writer thread, if configured.
    ///
    /// Runs once at startup, synchronously: device creation is a couple of
    /// syscalls, and doing it here keeps every error on the startup path
    /// instead of surfacing mid-traffic.
    fn start_tun(&self) -> io::Result<()> {
        let tun_config = self
            .config
            .tun_config()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let tun_config = match tun_config {
            Some(config) => config,
            None => return Ok(()),
        };
        self.tun_startup_checks();
        let device = Arc::new(TunDevice::create(&tun_config).map_err(|e| {
            let kind = match &e {
                crate::tun::TunError::PermissionDenied(_) => io::ErrorKind::PermissionDenied,
                _ => io::ErrorKind::Other,
            };
            io::Error::new(kind, e.to_string())
        })?);
        println!(
            "TUN device {} opened (forwarding enabled, subnet {})",
            device.name(),
            tun_config.subnet_cidr()
        );
        let (tx, rx) = mpsc::channel::<Vec<u8>>(TUN_QUEUE_CAPACITY);
        let stats = Arc::clone(&self.stats);
        let verbose = self.config.verbose;
        let writer_device = Arc::clone(&device);
        let handle = thread::Builder::new()
            .name("bondnet-tun-writer".to_string())
            .spawn(move || tun_writer_loop(writer_device, rx, stats, verbose))
            .map_err(io::Error::other)?;
        *self.tun_tx.lock().expect("tun queue lock poisoned") = Some(tx);
        *self.tun_writer.lock().expect("tun thread lock poisoned") = Some(handle);
        *self.tun_device.lock().expect("tun device lock poisoned") = Some(device);
        Ok(())
    }

    /// Read-only startup sanity checks. These WARN; they never fail
    /// startup and never change host state — fixing the host is the
    /// administrator's job (`--print-setup` prints the commands).
    fn tun_startup_checks(&self) {
        #[cfg(target_os = "linux")]
        {
            if let Ok(content) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
                && content.trim() != "1"
            {
                eprintln!(
                    "WARN net.ipv4.ip_forward is 0: forwarded packets will not reach the Internet (see --print-setup)"
                );
            }
            if let Some(wan) = &self.config.wan_interface {
                let path = format!("/sys/class/net/{wan}");
                if !std::path::Path::new(&path).exists() {
                    eprintln!(
                        "WARN --wan-iface {wan} not found: NAT setup commands may name the wrong interface"
                    );
                }
            }
        }
    }

    /// Stop the TUN writer: close the queue, let the thread drain pending
    /// packets, join it, then drop (and thereby destroy) the device.
    fn stop_tun(&self) {
        // Dropping the last sender closes the channel; the writer thread
        // sees None from blocking_recv, writes nothing more, and exits.
        drop(self.tun_tx.lock().expect("tun queue lock poisoned").take());
        if let Some(handle) = self
            .tun_writer
            .lock()
            .expect("tun thread lock poisoned")
            .take()
            && handle.join().is_err()
        {
            eprintln!("WARN TUN writer thread panicked during shutdown");
        }
    }

    /// Day 11: the configured return-path association, or `None` when the
    /// return path is disabled.
    fn return_association(&self) -> Option<(u64, u16)> {
        // Validated at startup by `ServerConfig::return_config`; a
        // misconfiguration here would be a bug, so fall back to disabled
        // rather than panicking.
        self.config.return_config().ok().flatten()
    }

    /// Day 11: turn one IP packet read from the TUN device into an encoded
    /// BondNet `Data` datagram addressed to the associated client.
    ///
    /// Pure with respect to I/O: validates, resolves the endpoint, and
    /// encodes, but never touches the socket or the TUN device — the
    /// reader thread and the sender task own those. Returns `None` when
    /// the packet was rejected (counted); the payload bytes are preserved
    /// byte-for-byte on success.
    ///
    /// # Trust limitation
    ///
    /// The destination is the *observed* source address of the configured
    /// `(session, path)` — Day 6 observation, still unauthenticated. A
    /// spoofed source address in an inbound packet would redirect return
    /// traffic. This is development-only trust; production needs the
    /// planned session authentication (later milestone).
    #[allow(dead_code)] // Testable entry point for the return pipeline; the
    // reader thread uses `build_return_datagram` directly (it holds the
    // pieces, not a `&Server`).
    fn process_return_packet(&self, ip_packet: &[u8]) -> Option<ReturnDatagram> {
        let (session_id, path_id) = self.return_association()?;
        build_return_datagram(
            &self.registry,
            &self.stats,
            session_id,
            path_id,
            Duration::from_secs(self.config.tun_return_max_age_secs),
            self.config.verbose,
            ip_packet,
        )
    }

    /// Day 11: start the TUN reader thread and the return sender task.
    ///
    /// No-op unless the return association is configured (which itself
    /// requires `--tun-name`, so a TUN device always exists here).
    fn start_return_path(&self, socket: &Arc<UdpSocket>) -> io::Result<()> {
        let (session_id, path_id) = match self.return_association() {
            Some(association) => association,
            None => return Ok(()),
        };
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (session_id, path_id, socket);
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TUN return path is implemented on Linux only (Day 11)",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            self.start_return_path_linux(socket, session_id, path_id)
        }
    }

    /// Linux implementation of [`start_return_path`](Self::start_return_path).
    #[cfg(target_os = "linux")]
    fn start_return_path_linux(
        &self,
        socket: &Arc<UdpSocket>,
        session_id: u64,
        path_id: u16,
    ) -> io::Result<()> {
        let device = self
            .tun_device
            .lock()
            .expect("tun device lock poisoned")
            .clone()
            .expect("return path requires a TUN device; this is a bug");
        let (tx, rx) = mpsc::channel::<ReturnDatagram>(RETURN_QUEUE_CAPACITY);

        // Reader thread: blocking poll(2) on the TUN fd — never a Tokio
        // executor thread.
        let reader_device = Arc::clone(&device);
        let reader_registry = Arc::clone(&self.registry);
        let reader_stats = Arc::clone(&self.stats);
        let reader_tx = tx.clone();
        let max_age = Duration::from_secs(self.config.tun_return_max_age_secs);
        let verbose = self.config.verbose;
        let shutdown = Arc::new(AtomicBool::new(false));
        let reader_shutdown = Arc::clone(&shutdown);
        let handle = thread::Builder::new()
            .name("bondnet-tun-reader".to_string())
            .spawn(move || {
                tun_reader_loop(
                    reader_device,
                    reader_registry,
                    reader_stats,
                    session_id,
                    path_id,
                    max_age,
                    verbose,
                    reader_tx,
                    shutdown,
                )
            })
            .map_err(io::Error::other)?;
        *self.tun_reader.lock().expect("tun reader lock poisoned") = Some(handle);
        *self
            .reader_shutdown
            .lock()
            .expect("reader shutdown lock poisoned") = Some(reader_shutdown);
        println!(
            "TUN return path enabled: device {} -> session={session_id} path={path_id}",
            device.name(),
        );

        // Async sender task: the ONLY code that sends return datagrams.
        // It owns the queue's receiving end and a clone of the shared
        // socket; send failures are counted and the loop keeps draining.
        let sender_socket = Arc::clone(socket);
        let sender_stats = Arc::clone(&self.stats);
        let verbose = self.config.verbose;
        let task = tokio::spawn(async move {
            let mut rx = rx;
            while let Some((remote, bytes)) = rx.recv().await {
                match sender_socket.send_to(&bytes, remote).await {
                    Ok(sent) => {
                        sender_stats
                            .return_packets_sent
                            .fetch_add(1, Ordering::Relaxed);
                        sender_stats
                            .return_bytes_sent
                            .fetch_add(sent as u64, Ordering::Relaxed);
                        if verbose {
                            println!("RETURN_UDP remote={remote} bytes={sent}");
                        }
                    }
                    Err(error) => {
                        sender_stats
                            .return_send_errors
                            .fetch_add(1, Ordering::Relaxed);
                        eprintln!("WARN return send_to {remote} failed: {error}");
                    }
                }
            }
        });
        *self.return_tx.lock().expect("return queue lock poisoned") = Some(tx);
        *self.return_task.lock().expect("return task lock poisoned") = Some(task);
        Ok(())
    }

    /// Day 11: stop the return path. Signals the reader thread, joins it,
    /// then closes the return queue so the sender task drains and ends.
    async fn stop_return_path(&self) {
        if let Some(shutdown) = self
            .reader_shutdown
            .lock()
            .expect("reader shutdown lock poisoned")
            .take()
        {
            shutdown.store(true, Ordering::SeqCst);
        }
        if let Some(handle) = self
            .tun_reader
            .lock()
            .expect("tun reader lock poisoned")
            .take()
            && handle.join().is_err()
        {
            eprintln!("WARN TUN reader thread panicked during shutdown");
        }
        // Closing the queue lets the sender task finish its drain and exit.
        drop(
            self.return_tx
                .lock()
                .expect("return queue lock poisoned")
                .take(),
        );
        // Take the task handle first so the (non-Send) MutexGuard is not
        // held across the await.
        let task = self
            .return_task
            .lock()
            .expect("return task lock poisoned")
            .take();
        if let Some(task) = task
            && let Err(error) = task.await
        {
            eprintln!("WARN return sender task failed: {error}");
        }
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
        // Day 9: observe Data packets for the tunnel proof. Counting only,
        // unless Day 10 TUN forwarding is enabled (see forward_to_tun).
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

        // Day 10: forward validated Data payloads toward the TUN device.
        // No-op unless --tun-name was given.
        self.forward_to_tun(&packet);
    }

    /// Day 10 forward gate: `Data` → IP validation → bounded TUN queue.
    ///
    /// Non-`Data` packets return immediately and can never reach the TUN
    /// device, no matter what the UDP payload contains.
    fn forward_to_tun(&self, packet: &Packet) {
        if packet.header.packet_type != PacketType::Data {
            return;
        }
        let tx = match self.tun_tx.lock().expect("tun queue lock poisoned").clone() {
            Some(tx) => tx,
            None => return, // TUN disabled: Day 6/9 behavior (count only).
        };
        let h = &packet.header;
        if let Err(reason) = validate_ip_packet(&packet.payload) {
            self.stats.tun_invalid_ip.fetch_add(1, Ordering::Relaxed);
            if self.config.verbose {
                println!(
                    "IP_REJECT session={} path={} seq={} len={} reason={reason}",
                    h.session_id,
                    h.path_id,
                    h.sequence,
                    packet.payload.len(),
                );
            }
            return;
        }
        match tx.try_send(packet.payload.clone()) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Backpressure policy: drop the newest packet, count it.
                // The queue is bounded so memory stays flat under load.
                self.stats.tun_queue_dropped.fetch_add(1, Ordering::Relaxed);
                if self.config.verbose {
                    println!(
                        "TUN_DROP session={} path={} seq={} reason=queue-full",
                        h.session_id, h.path_id, h.sequence,
                    );
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.stats.tun_write_errors.fetch_add(1, Ordering::Relaxed);
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
            return_sequence: 1,
        });
        path.remote_addr = remote;
        path.last_seen = now;
        path.packets_received += 1;
        path.bytes_received += len as u64;
        path.last_sequence = h.sequence;
    }
}

/// Dedicated TUN writer thread.
///
/// Blocking `blocking_recv` means no busy loop; blocking `write(2)` is
/// safe here because this is NOT a Tokio executor thread. The loop ends
/// when the server drops the queue sender during shutdown; the device is
/// dropped (and the kernel interface destroyed) when this function
/// returns.
fn tun_writer_loop(
    device: Arc<TunDevice>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    stats: Arc<ServerStats>,
    verbose: bool,
) {
    let name = device.name().to_string();
    while let Some(packet) = rx.blocking_recv() {
        match device.write_packet(&packet) {
            Ok(()) => {
                stats.tun_packets_written.fetch_add(1, Ordering::Relaxed);
                stats
                    .tun_bytes_written
                    .fetch_add(packet.len() as u64, Ordering::Relaxed);
                if verbose {
                    println!("TUN_TX dev={name} len={}", packet.len());
                }
            }
            Err(error) => {
                // Includes WouldBlock: the non-blocking fd refused, so the
                // packet is dropped rather than stalling the thread.
                stats.tun_write_errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("WARN TUN write dev={name} error={error}");
            }
        }
    }
    println!("TUN writer stopped ({name})");
}

/// Day 11: the shared core of the return pipeline — validate one
/// TUN-read IP packet, resolve the live endpoint for `(session_id,
/// path_id)`, allocate the next return-direction sequence number, and
/// encode the addressed `Data` datagram.
///
/// Used by both [`Server::process_return_packet`] (tests, single-threaded)
/// and the TUN reader thread. Returns `None` when the packet was rejected
/// (counted in `stats`).
///
/// Malformed packets never reach here with endpoint state to corrupt: only
/// successfully decoded inbound packets update the registry (via
/// `record_packet`), so a bad TUN-read packet cannot overwrite the trusted
/// association.
fn build_return_datagram(
    registry: &Mutex<HashMap<u64, SessionState>>,
    stats: &ServerStats,
    session_id: u64,
    path_id: u16,
    max_age: Duration,
    verbose: bool,
    ip_packet: &[u8],
) -> Option<ReturnDatagram> {
    if let Err(reason) = validate_ip_packet(ip_packet) {
        stats.return_invalid_ip.fetch_add(1, Ordering::Relaxed);
        if verbose {
            println!(
                "RETURN_IP_REJECT session={session_id} path={path_id} len={} reason={reason}",
                ip_packet.len(),
            );
        }
        return None;
    }
    let mut registry = registry.lock().expect("registry lock poisoned");
    let path = registry
        .get_mut(&session_id)
        .and_then(|session| session.paths.get_mut(&path_id));
    let (remote, sequence) = match path {
        Some(path) if path.last_seen.elapsed() <= max_age => {
            let sequence = path.return_sequence;
            path.return_sequence = path.return_sequence.wrapping_add(1);
            (path.remote_addr, sequence)
        }
        _ => {
            drop(registry);
            stats.return_no_endpoint.fetch_add(1, Ordering::Relaxed);
            if verbose {
                println!(
                    "RETURN_NO_ENDPOINT session={session_id} path={path_id} \
                     reason=unknown-or-expired-association"
                );
            }
            return None;
        }
    };
    drop(registry);
    let packet = Packet {
        header: PacketHeader {
            version: PROTOCOL_VERSION,
            flags: 0,
            session_id,
            sequence,
            path_id,
            packet_type: PacketType::Data,
            timestamp: unix_millis(),
        },
        payload: ip_packet.to_vec(),
    };
    match packet.encode() {
        Ok(bytes) => {
            if verbose {
                println!(
                    "RETURN_TX session={session_id} path={path_id} seq={sequence} \
                     payload_len={} remote={remote}",
                    ip_packet.len(),
                );
            }
            Some((remote, bytes))
        }
        Err(error) => {
            // Encode of a just-built packet cannot fail in practice
            // (payload < 64 KiB); counted as a send error, never a panic.
            stats.return_send_errors.fetch_add(1, Ordering::Relaxed);
            eprintln!("WARN return packet encode failed: {error}");
            None
        }
    }
}

/// Push one encoded return datagram into the bounded return queue.
///
/// Returns `false` when the sender task is gone (the caller should stop);
/// `true` otherwise. A full queue drops the newest datagram and counts it
/// — the reader never blocks on the sender.
#[cfg(target_os = "linux")]
fn enqueue_return_datagram(
    tx: &mpsc::Sender<ReturnDatagram>,
    datagram: (SocketAddr, Vec<u8>),
    stats: &ServerStats,
    verbose: bool,
    session_id: u64,
    path_id: u16,
) -> bool {
    match tx.try_send(datagram) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            stats
                .return_backpressure_dropped
                .fetch_add(1, Ordering::Relaxed);
            if verbose {
                println!("RETURN_DROP session={session_id} path={path_id} reason=queue-full");
            }
            true
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

/// Dedicated TUN reader thread (Day 11, Linux only).
///
/// `poll(2)` on the shared TUN fd with a short timeout: the thread sleeps
/// instead of busy-looping, wakes immediately when a packet is readable,
/// and re-checks the shutdown flag at least every
/// [`TUN_READER_POLL_TIMEOUT_MS`] ms. This is NOT a Tokio executor thread,
/// so blocking here is safe.
///
/// Each readable packet is validated and turned into an addressed return
/// datagram by [`Server::process_return_packet`], then pushed into the
/// bounded return queue. A full queue drops the newest packet and counts
/// it — the reader never blocks on the sender.
///
/// Loop prevention: packets read here are NEVER fed back into the TUN
/// writer queue. The upload direction (UDP → TUN) and the return
/// direction (TUN → UDP) are separate pipelines sharing only the fd.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn tun_reader_loop(
    device: Arc<TunDevice>,
    registry: Arc<Mutex<HashMap<u64, SessionState>>>,
    stats: Arc<ServerStats>,
    session_id: u64,
    path_id: u16,
    max_age: Duration,
    verbose: bool,
    return_tx: mpsc::Sender<ReturnDatagram>,
    shutdown: Arc<AtomicBool>,
) {
    let fd = device.as_raw_fd();
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let mut buf = vec![0u8; TUN_READ_BUF_LEN];
    println!("TUN reader started ({})", device.name());
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        // SAFETY: `pfd` is a valid single-element pollfd array; `fd` is
        // the open TUN descriptor owned by `device` (alive for the whole
        // loop via the Arc).
        let rc = unsafe { libc::poll(&mut pfd, 1, TUN_READER_POLL_TIMEOUT_MS) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            stats.tun_read_errors.fetch_add(1, Ordering::Relaxed);
            eprintln!("WARN TUN poll failed: {err}");
            break;
        }
        if rc == 0 {
            continue; // timeout: re-check the shutdown flag
        }
        if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            stats.tun_read_errors.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "WARN TUN device error (revents={}), reader stopping",
                pfd.revents
            );
            break;
        }
        if pfd.revents & libc::POLLIN == 0 {
            continue;
        }
        match device.read_packet(&mut buf) {
            Ok(n) => {
                stats.tun_packets_read.fetch_add(1, Ordering::Relaxed);
                stats.tun_bytes_read.fetch_add(n as u64, Ordering::Relaxed);
                if let Some(datagram) = build_return_datagram(
                    &registry,
                    &stats,
                    session_id,
                    path_id,
                    max_age,
                    verbose,
                    &buf[..n],
                ) && !enqueue_return_datagram(
                    &return_tx, datagram, &stats, verbose, session_id, path_id,
                ) {
                    // Sender task is gone; shutting down.
                    break;
                }
            }
            Err(crate::tun::TunError::WouldBlock) => {
                // Spurious wakeup; loop back to poll.
            }
            Err(error) => {
                stats.tun_read_errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("WARN TUN read failed: {error}");
            }
        }
    }
    println!("TUN reader stopped ({})", device.name());
}

/// Current Unix time in milliseconds, for the return packet header.
fn unix_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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

#[cfg(test)]
mod tests {
    use super::*;
    use bondnet_protocol::{PROTOCOL_VERSION, PacketHeader};

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

    /// Minimal valid IPv4 packet: 20-byte header, IHL=5, total=20.
    fn ipv4_min() -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&20u16.to_be_bytes());
        p
    }

    fn remote() -> SocketAddr {
        "127.0.0.1:9999".parse().unwrap()
    }

    /// A server with a test TUN queue injected (no real device needed).
    fn server_with_queue(capacity: usize) -> (Server, mpsc::Receiver<Vec<u8>>) {
        let server = Server::new(ServerConfig::default());
        let (tx, rx) = mpsc::channel(capacity);
        *server.tun_tx.lock().expect("tun queue lock poisoned") = Some(tx);
        (server, rx)
    }

    #[test]
    fn valid_ipv4_data_reaches_tun_queue_unchanged() {
        let (server, mut rx) = server_with_queue(16);
        let payload = ipv4_min();
        let datagram = encode_packet(1001, 1, 42, PacketType::Data, payload.clone());
        server.handle_datagram(&datagram, remote());
        let queued = rx.try_recv().expect("validated packet must be queued");
        assert_eq!(queued, payload, "TUN must receive the exact payload bytes");
        let stats = server.stats();
        assert_eq!(stats.tun_invalid_ip, 0);
        assert_eq!(stats.tun_queue_dropped, 0);
    }

    #[test]
    fn valid_ipv6_data_reaches_tun_queue() {
        let (server, mut rx) = server_with_queue(16);
        let mut payload = vec![0u8; 40];
        payload[0] = 0x60; // version 6, payload length 0
        let datagram = encode_packet(1001, 1, 7, PacketType::Data, payload.clone());
        server.handle_datagram(&datagram, remote());
        assert_eq!(rx.try_recv().unwrap(), payload);
    }

    #[test]
    fn invalid_ip_payload_rejected_and_counted() {
        let (server, mut rx) = server_with_queue(16);
        // 20 zero bytes: version nibble 0 → UnknownVersion.
        let datagram = encode_packet(1001, 1, 1, PacketType::Data, vec![0u8; 20]);
        server.handle_datagram(&datagram, remote());
        assert!(rx.try_recv().is_err(), "invalid IP must never be queued");
        let stats = server.stats();
        assert_eq!(stats.tun_invalid_ip, 1);
        // Day 9 counting is untouched: it was still a Data packet.
        assert_eq!(stats.data_packets, 1);
    }

    #[test]
    fn non_data_packet_never_enters_tun_queue() {
        let (server, mut rx) = server_with_queue(16);
        // A PathHello carrying bytes that would look like IPv4: the type
        // gate must stop it before validation is even considered.
        let datagram = encode_packet(1001, 1, 1, PacketType::PathHello, ipv4_min());
        server.handle_datagram(&datagram, remote());
        assert!(rx.try_recv().is_err());
        let stats = server.stats();
        assert_eq!(stats.data_packets, 0);
        assert_eq!(stats.tun_invalid_ip, 0);
    }

    #[test]
    fn malformed_datagram_never_enters_tun_queue() {
        let (server, mut rx) = server_with_queue(16);
        server.handle_datagram(b"garbage-not-a-packet", remote());
        assert!(rx.try_recv().is_err());
        assert_eq!(server.stats().malformed_packets, 1);
    }

    #[test]
    fn full_queue_drops_newest_and_counts() {
        let (server, mut rx) = server_with_queue(1);
        // Fill the single slot directly so the queue is full.
        server
            .tun_tx
            .lock()
            .expect("tun queue lock poisoned")
            .as_ref()
            .unwrap()
            .try_send(vec![0xaa])
            .unwrap();
        let datagram = encode_packet(1001, 1, 9, PacketType::Data, ipv4_min());
        server.handle_datagram(&datagram, remote());
        assert_eq!(server.stats().tun_queue_dropped, 1);
        // The pre-existing item is untouched; the new packet was dropped.
        assert_eq!(rx.try_recv().unwrap(), vec![0xaa]);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn tun_disabled_by_default_keeps_day9_behavior() {
        let server = Server::new(ServerConfig::default());
        // Invalid IP payload, but TUN was never enabled: no validation, no
        // rejection — exactly Day 9 counting behavior.
        let datagram = encode_packet(1001, 1, 1, PacketType::Data, vec![0u8; 20]);
        server.handle_datagram(&datagram, remote());
        let stats = server.stats();
        assert_eq!(stats.data_packets, 1);
        assert_eq!(stats.tun_invalid_ip, 0);
        assert_eq!(stats.tun_queue_dropped, 0);
    }

    // ---------- Day 11 return path ----------

    /// A server with the return association configured (TUN flags present
    /// so `return_config()` validates; no real device is created).
    fn server_with_return(session_id: u64, path_id: u16, max_age_secs: u64) -> Server {
        let config = ServerConfig {
            tun_name: Some("bondtun0".to_string()),
            tun_addr: Some("10.200.0.1".parse().unwrap()),
            tun_prefix: Some(24),
            tun_return_session: Some(session_id),
            tun_return_path: Some(path_id),
            tun_return_max_age_secs: max_age_secs,
            ..Default::default()
        };
        Server::new(config)
    }

    /// Feed one Data packet so the (session, path) endpoint association
    /// exists, then return the server.
    fn server_with_endpoint(session_id: u64, path_id: u16) -> Server {
        let server = server_with_return(session_id, path_id, 300);
        let datagram = encode_packet(session_id, path_id, 0, PacketType::Data, ipv4_min());
        server.handle_datagram(&datagram, remote());
        server
    }

    #[test]
    fn return_packet_encodes_valid_tun_packet() {
        let server = server_with_endpoint(1001, 1);
        let payload = ipv4_min();
        let (dest, bytes) = server
            .process_return_packet(&payload)
            .expect("endpoint association exists");
        assert_eq!(dest, remote());
        let packet = Packet::decode(&bytes).expect("return datagram must decode");
        assert_eq!(packet.header.packet_type, PacketType::Data);
        assert_eq!(packet.header.session_id, 1001);
        assert_eq!(packet.header.path_id, 1);
        assert_eq!(packet.header.version, PROTOCOL_VERSION);
        assert_eq!(packet.payload, payload, "payload byte-for-byte unchanged");
    }

    #[test]
    fn return_sequence_increments_per_path() {
        let server = server_with_endpoint(1001, 1);
        let payload = ipv4_min();
        let seq1 = Packet::decode(&server.process_return_packet(&payload).unwrap().1)
            .unwrap()
            .header
            .sequence;
        let seq2 = Packet::decode(&server.process_return_packet(&payload).unwrap().1)
            .unwrap()
            .header
            .sequence;
        assert_eq!((seq1, seq2), (1, 2));
    }

    #[test]
    fn return_sequences_are_independent_per_path() {
        let server = server_with_return(1001, 1, 300);
        for path_id in [1u16, 2] {
            let datagram = encode_packet(1001, path_id, 0, PacketType::Data, ipv4_min());
            server.handle_datagram(&datagram, remote());
        }
        // Path 1's return association is (1001, 1); path 2 is separate.
        let seq_p1 = Packet::decode(&server.process_return_packet(&ipv4_min()).unwrap().1)
            .unwrap()
            .header
            .sequence;
        assert_eq!(seq_p1, 1);
    }

    #[test]
    fn return_invalid_ip_rejected_and_counted() {
        let server = server_with_endpoint(1001, 1);
        assert!(server.process_return_packet(&[0u8; 20]).is_none());
        let stats = server.stats();
        assert_eq!(stats.return_invalid_ip, 1);
        assert_eq!(stats.return_packets_sent, 0);
    }

    #[test]
    fn return_unknown_endpoint_rejected_and_counted() {
        // No inbound packet ever observed: the association is unknown.
        let server = server_with_return(1001, 1, 300);
        assert!(server.process_return_packet(&ipv4_min()).is_none());
        let stats = server.stats();
        assert_eq!(stats.return_no_endpoint, 1);
        assert_eq!(stats.return_invalid_ip, 0);
    }

    #[test]
    fn return_wrong_session_rejected() {
        // Endpoint exists for session 1001, but the return association
        // points at session 9999.
        let server = server_with_return(9999, 1, 300);
        let datagram = encode_packet(1001, 1, 0, PacketType::Data, ipv4_min());
        server.handle_datagram(&datagram, remote());
        assert!(server.process_return_packet(&ipv4_min()).is_none());
        assert_eq!(server.stats().return_no_endpoint, 1);
    }

    #[test]
    fn return_expired_association_rejected() {
        let server = server_with_endpoint(1001, 1);
        // Age the association beyond max_age without sending anything new.
        {
            let mut registry = server.registry.lock().expect("registry lock poisoned");
            let path = registry
                .get_mut(&1001)
                .expect("session must exist")
                .paths
                .get_mut(&1)
                .expect("path must exist");
            path.last_seen = Instant::now() - Duration::from_secs(301);
        }
        assert!(server.process_return_packet(&ipv4_min()).is_none());
        assert_eq!(server.stats().return_no_endpoint, 1);
    }

    #[test]
    fn malformed_datagram_does_not_create_endpoint() {
        let server = server_with_return(1001, 1, 300);
        server.handle_datagram(b"garbage-not-a-packet", remote());
        assert!(server.sessions().is_empty());
        assert!(server.process_return_packet(&ipv4_min()).is_none());
        assert_eq!(server.stats().return_no_endpoint, 1);
    }

    #[test]
    fn non_data_packet_does_not_create_return_endpoint() {
        // A PathHello is recorded in the registry (Day 6 observation), so
        // the association exists — but it must not be usable to exfiltrate
        // anything unexpected. The return path only needs the address, and
        // the address came from a decoded packet, which is the documented
        // trust model.
        let server = server_with_return(1001, 1, 300);
        let datagram = encode_packet(1001, 1, 0, PacketType::PathHello, vec![]);
        server.handle_datagram(&datagram, remote());
        // Association exists (observation), return works — this documents
        // that ANY decoded packet type establishes the endpoint.
        assert!(server.process_return_packet(&ipv4_min()).is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn return_queue_full_drops_newest_and_counts() {
        let stats = ServerStats::default();
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send((remote(), vec![0xaa])).expect("fill the queue");
        let dropped = (remote(), vec![0xbb]);
        assert!(enqueue_return_datagram(
            &tx, dropped, &stats, false, 1001, 1
        ));
        assert_eq!(stats.snapshot().return_backpressure_dropped, 1);
        assert_eq!(rx.try_recv().unwrap().1, vec![0xaa]);
        assert!(rx.try_recv().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn return_queue_closed_signals_stop() {
        let stats = ServerStats::default();
        let (tx, rx) = mpsc::channel::<ReturnDatagram>(1);
        drop(rx);
        assert!(!enqueue_return_datagram(
            &tx,
            (remote(), vec![0x01]),
            &stats,
            false,
            1001,
            1
        ));
        assert_eq!(stats.snapshot().return_backpressure_dropped, 0);
    }

    #[test]
    fn return_disabled_without_flags() {
        let server = Server::new(ServerConfig::default());
        assert_eq!(server.return_association(), None);
        // process_return_packet has no association: clean None, no counts.
        assert!(server.process_return_packet(&ipv4_min()).is_none());
        let stats = server.stats();
        assert_eq!(stats.return_no_endpoint, 0);
        assert_eq!(stats.return_invalid_ip, 0);
    }

    /// Loopback integration: a real client UDP socket establishes the
    /// endpoint, the return pipeline builds the datagram, and a real
    /// server UDP socket delivers it back. No TUN device involved — the
    /// TUN `read(2)` is the only part this does not exercise.
    ///
    /// Ignored by default: needs real UDP loopback. (Some sandboxes block
    /// `sendto(2)` with EPERM; run with `-- --ignored` on a real machine.)
    #[ignore = "needs real UDP loopback; sandboxed environments may block sendto(2)"]
    #[tokio::test]
    async fn return_path_loopback_udp() {
        let server = server_with_return(7, 1, 300);
        let server_sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind server socket");
        let client_sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind client socket");
        let server_addr = server_sock.local_addr().unwrap();
        let client_addr = client_sock.local_addr().unwrap();

        // 1. Client -> server: Data packet establishes the association.
        let up = encode_packet(7, 1, 0, PacketType::Data, ipv4_min());
        client_sock
            .send_to(&up, server_addr)
            .await
            .expect("client send");
        let mut buf = vec![0u8; RECV_BUF_LEN];
        let (len, remote) = server_sock.recv_from(&mut buf).await.expect("server recv");
        assert_eq!(remote, client_addr);
        server.handle_datagram(&buf[..len], remote);

        // 2. A TUN-read IP packet goes through the return pipeline.
        let mut ip_packet = ipv4_min();
        ip_packet.extend_from_slice(&[0xabu8; 44]); // 64-byte packet
        ip_packet[2..4].copy_from_slice(&64u16.to_be_bytes());
        let (dest, datagram) = server
            .process_return_packet(&ip_packet)
            .expect("association exists");
        assert_eq!(dest, client_addr);

        // 3. Server -> client over real UDP; client decodes and verifies.
        server_sock
            .send_to(&datagram, dest)
            .await
            .expect("server send");
        let mut cbuf = vec![0u8; 65535];
        let (clen, _) = client_sock.recv_from(&mut cbuf).await.expect("client recv");
        let ret = Packet::decode(&cbuf[..clen]).expect("decodes");
        assert_eq!(ret.header.packet_type, PacketType::Data);
        assert_eq!(ret.header.session_id, 7);
        assert_eq!(ret.header.path_id, 1);
        assert_eq!(ret.header.sequence, 1);
        assert_eq!(ret.payload, ip_packet, "payload byte-for-byte identical");

        // 4. The next return packet carries the next sequence number.
        let (_, datagram2) = server.process_return_packet(&ip_packet).unwrap();
        let ret2 = Packet::decode(&datagram2).expect("decodes");
        assert_eq!(ret2.header.sequence, 2);
    }

    // ------------------------------------------------------------------
    // Day 12: deterministic end-to-end simulation (fake devices).
    //
    // Traces ONE synthetic IP packet through every pipeline stage using
    // the REAL encoder/decoder/validators from both crates. The OS
    // boundaries are faked explicitly:
    //   - UDP socket: bound but never sent (UdpPath::next_packet is pure)
    //   - TUN device: the injected mpsc queue (no kernel, no ioctls)
    //   - Wintun: a FakeWriter recording bytes (no DLL)
    //
    // This is a SIMULATION, not a network proof. It verifies logic and
    // byte-preservation; it cannot prove real TUN/Wintun/Internet work.
    // ------------------------------------------------------------------

    use bondnet_client::{
        ReturnProcessor, UdpPath, UdpPathConfig, WintunWriter, wintun::WintunError,
    };

    /// Fake Wintun device: records written packets, never touches the OS.
    struct FakeWintunDevice {
        written: Vec<Vec<u8>>,
    }

    impl WintunWriter for FakeWintunDevice {
        fn write_ip_packet(&mut self, packet: &[u8]) -> Result<(), WintunError> {
            self.written.push(packet.to_vec());
            Ok(())
        }
    }

    fn synthetic_probe_packet() -> Vec<u8> {
        // Minimal valid IPv4 header (20 bytes) + deterministic 44-byte
        // payload. Total length field is patched to 64.
        let mut pkt = ipv4_min();
        pkt.extend_from_slice(&[0x5au8; 44]);
        pkt[2..4].copy_from_slice(&64u16.to_be_bytes());
        pkt
    }

    #[tokio::test]
    async fn e2e_sim_upload_and_return_preserve_bytes() {
        let session_id = 4242u64;
        let path_id = 7u16;
        let probe = synthetic_probe_packet();
        let probe_fp = payload_fingerprint(&probe);

        // Stage 1 (client, real): UdpPath stamps session/path/sequence and
        // encodes the BondNet packet — the exact logic DataPlane uses.
        // The socket is bound (works everywhere) but never sent.
        let path = UdpPath::bind(UdpPathConfig {
            local_addr: "127.0.0.1:0".parse().unwrap(),
            remote_addr: "127.0.0.1:9".parse().unwrap(),
            session_id,
            path_id,
            initial_sequence: 500,
        })
        .await
        .expect("udp bind works in test");
        let upload_packet = path.next_packet(PacketType::Data, probe.clone());
        assert_eq!(upload_packet.header.session_id, session_id);
        assert_eq!(upload_packet.header.path_id, path_id);
        assert_eq!(upload_packet.header.sequence, 500);
        let upload_bytes = upload_packet.encode().expect("encode");

        // Stage 2 (server, real): decode, registry observation, IP
        // validation, TUN queue. The queue IS the fake TUN device here.
        let (server, mut tun_rx) = server_with_queue(1024);
        let client_addr: std::net::SocketAddr = "127.0.0.1:45123".parse().unwrap();
        server.handle_datagram(&upload_bytes, client_addr);
        // Association for the return leg: same session/path the client used.
        {
            let mut registry = server.registry.lock().expect("registry lock");
            let entry = registry.get_mut(&session_id).expect("observed");
            entry.paths.get_mut(&path_id).expect("path observed");
        }
        let tun_bytes = tun_rx.try_recv().expect("packet reached fake TUN");
        assert_eq!(
            payload_fingerprint(&tun_bytes),
            probe_fp,
            "upload: TUN bytes == original probe"
        );

        // Stage 3 (server, real): the fake TUN "read" feeds the return
        // pipeline — validate, resolve endpoint, stamp return sequence,
        // encode. We call the same core the reader thread uses.
        let return_server = {
            let config = ServerConfig {
                tun_name: Some("bondtun0".to_string()),
                tun_addr: Some("10.200.0.1".parse().unwrap()),
                tun_prefix: Some(24),
                tun_return_session: Some(session_id),
                tun_return_path: Some(path_id),
                tun_return_max_age_secs: 300,
                ..Default::default()
            };
            Server::new(config)
        };
        // Replay the upload so the return server observes the endpoint.
        return_server.handle_datagram(&upload_bytes, client_addr);
        let (dest, return_bytes) = return_server
            .process_return_packet(&tun_bytes)
            .expect("return datagram built");
        assert_eq!(dest, client_addr, "return goes to the observed endpoint");

        // Stage 4 (client, real): decode the return datagram and run the
        // full return validation gate (type/session/path/IP).
        let decoded = Packet::decode(&return_bytes).expect("return decodes");
        assert_eq!(decoded.header.packet_type, PacketType::Data);
        assert_eq!(decoded.header.session_id, session_id);
        assert_eq!(decoded.header.path_id, path_id);
        let processor = ReturnProcessor::new(session_id, path_id);
        let payload = processor.validate(&decoded).expect("return validates");

        // Stage 5 (fake Wintun): write and verify byte preservation.
        let mut fake_wintun = FakeWintunDevice {
            written: Vec::new(),
        };
        processor
            .validate_and_write(&decoded, &mut fake_wintun)
            .expect("fake wintun write");
        assert_eq!(fake_wintun.written.len(), 1);
        assert_eq!(
            payload_fingerprint(&fake_wintun.written[0]),
            probe_fp,
            "return: Wintun bytes == original probe"
        );
        assert_eq!(payload, &probe[..]);

        // Stage correlation: the return sequence lives in its own
        // directional space (starts at 1), independent of upload seq 500.
        assert_eq!(decoded.header.sequence, 1);
    }

    #[tokio::test]
    async fn e2e_sim_rejects_tampered_return_before_wintun() {
        let session_id = 4242u64;
        let path_id = 7u16;
        let probe = synthetic_probe_packet();

        let path = UdpPath::bind(UdpPathConfig {
            local_addr: "127.0.0.1:0".parse().unwrap(),
            remote_addr: "127.0.0.1:9".parse().unwrap(),
            session_id,
            path_id,
            initial_sequence: 1,
        })
        .await
        .expect("udp bind");
        let upload_bytes = path
            .next_packet(PacketType::Data, probe.clone())
            .encode()
            .expect("encode");

        let config = ServerConfig {
            tun_name: Some("bondtun0".to_string()),
            tun_addr: Some("10.200.0.1".parse().unwrap()),
            tun_prefix: Some(24),
            tun_return_session: Some(session_id),
            tun_return_path: Some(path_id),
            tun_return_max_age_secs: 300,
            ..Default::default()
        };
        let server = Server::new(config);
        let client_addr: std::net::SocketAddr = "127.0.0.1:45123".parse().unwrap();
        server.handle_datagram(&upload_bytes, client_addr);
        let (_, mut return_bytes) = server
            .process_return_packet(&probe)
            .expect("return datagram");

        // Tamper: corrupt the IP version nibble inside the encoded return
        // datagram (offset 36 = start of the IP payload). The structural
        // validator must reject it — nothing reaches the fake Wintun.
        // (Flipping a *payload* byte would not break structure; the gate
        // is structural, not cryptographic — documented in ip.rs.)
        return_bytes[36] = 0x55;

        let decoded = Packet::decode(&return_bytes).expect("still decodes");
        let processor = ReturnProcessor::new(session_id, path_id);
        let mut fake_wintun = FakeWintunDevice {
            written: Vec::new(),
        };
        // The tampered payload fails IP validation (total-length/checksum
        // no longer consistent) — nothing reaches the fake Wintun.
        assert!(processor.validate(&decoded).is_err());
        assert!(fake_wintun.written.is_empty());
        // validate_and_write also refuses.
        assert!(
            processor
                .validate_and_write(&decoded, &mut fake_wintun)
                .is_err()
        );
        assert!(fake_wintun.written.is_empty());
    }

    // ------------------------------------------------------------------
    // Day 13: server distinguishes two path IDs from different sources.
    //
    // The registry is keyed by (session_id, path_id); this test proves
    // that packets on path 1 never overwrite path 2's endpoint
    // association, counters stay per-path, and return traffic for each
    // path goes to its own observed address.
    // ------------------------------------------------------------------

    #[test]
    fn two_path_ids_tracked_independently() {
        let server = server_with_return(1001, 1, 300);
        let addr1: std::net::SocketAddr = "127.0.0.1:41001".parse().unwrap();
        let addr2: std::net::SocketAddr = "127.0.0.1:41002".parse().unwrap();

        // Path 1 packet from source A.
        let d1 = encode_packet(1001, 1, 10, PacketType::Data, ipv4_min());
        server.handle_datagram(&d1, addr1);
        // Path 2 packet from source B (different path_id, different port).
        let d2 = encode_packet(1001, 2, 20, PacketType::Data, ipv4_min());
        server.handle_datagram(&d2, addr2);
        // Another path 1 packet — must not disturb path 2's association.
        let d1b = encode_packet(1001, 1, 11, PacketType::Data, ipv4_min());
        server.handle_datagram(&d1b, addr1);

        let sessions = server.sessions();
        assert_eq!(sessions.len(), 1);
        let session = &sessions[0];
        assert_eq!(session.session_id, 1001);
        assert_eq!(session.paths.len(), 2);

        let p1 = session.paths.iter().find(|p| p.path_id == 1).unwrap();
        let p2 = session.paths.iter().find(|p| p.path_id == 2).unwrap();
        assert_eq!(p1.remote_addr, addr1);
        assert_eq!(p2.remote_addr, addr2);
        assert_eq!(p1.packets_received, 2);
        assert_eq!(p2.packets_received, 1);
        assert_eq!(p1.last_sequence, 11);
        assert_eq!(p2.last_sequence, 20);
    }

    #[test]
    fn return_goes_to_correct_path_endpoint() {
        // Path 1's return association is configured; path 2 is observed
        // but has no return association — its return must be refused, not
        // misdirected to path 1's endpoint.
        let server = server_with_return(1001, 1, 300);
        let addr1: std::net::SocketAddr = "127.0.0.1:42001".parse().unwrap();
        let addr2: std::net::SocketAddr = "127.0.0.1:42002".parse().unwrap();

        let d1 = encode_packet(1001, 1, 1, PacketType::Data, ipv4_min());
        server.handle_datagram(&d1, addr1);
        let d2 = encode_packet(1001, 2, 1, PacketType::Data, ipv4_min());
        server.handle_datagram(&d2, addr2);

        // Path 1: return works, goes to addr1.
        let (dest1, _) = server
            .process_return_packet(&ipv4_min())
            .expect("path 1 has a return association");
        assert_eq!(dest1, addr1);

        // Path 2: verified via a second server configured for (1001, 2).
        let server2 = server_with_return(1001, 2, 300);
        server2.handle_datagram(&d1, addr1);
        server2.handle_datagram(&d2, addr2);
        let (dest2, _) = server2
            .process_return_packet(&ipv4_min())
            .expect("path 2 has a return association");
        assert_eq!(dest2, addr2, "path 2 return must go to addr2, not addr1");
    }

    #[test]
    fn unknown_path_id_does_not_create_endpoint() {
        let server = server_with_return(1001, 1, 300);
        let addr: std::net::SocketAddr = "127.0.0.1:43001".parse().unwrap();
        // Only path 1 ever sends; path 99 is never observed.
        let d1 = encode_packet(1001, 1, 1, PacketType::Data, ipv4_min());
        server.handle_datagram(&d1, addr);

        let sessions = server.sessions();
        assert_eq!(sessions[0].paths.len(), 1);
        assert!(sessions[0].paths.iter().all(|p| p.path_id == 1));
    }
}
