//! Day 9 data plane: Wintun bytes → BondNet `Data` packet → `UdpPath`.
//!
//! The data plane is deliberately thin. It validates one inner Layer-3
//! packet, wraps it in the existing `PacketType::Data` envelope with the
//! payload bytes byte-for-byte untouched, and hands it to the existing
//! Day 7 `UdpPath`. It owns no socket and performs no routing, no
//! encryption, no scheduling, no retransmission, no NAT — those are all
//! later milestones.
//!
//! # Plaintext warning
//!
//! Payloads travel unencrypted, exactly as on Day 7. Development use
//! only — never send secrets through this path.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bondnet_protocol::{HEADER_LEN, PacketType};

use crate::error::TransportError;
use crate::transport::UdpPath;

/// Largest inner (Wintun Layer-3) packet the data plane accepts, in
/// bytes: 1500, the standard Ethernet-class IP packet size.
///
/// The resulting UDP datagram is `HEADER_LEN + 1500 = 1536` bytes, which
/// can exceed a 1500-byte path MTU and depend on IP fragmentation on the
/// real network. That is accepted for the Day 9 proof; real MTU/MSS
/// handling (clamping, discovery, or an explicit pre-fragmentation
/// policy) is a Day 10+ task. Oversized inner packets are rejected here
/// and counted — never fragmented by BondNet itself.
pub const MAX_WINTUN_PACKET_LEN: usize = 1500;

/// Bounded handoff between the blocking Wintun reader thread and the
/// async UDP sender: 1024 packets × 1500 bytes ≈ 1.5 MiB worst case. A
/// fast Wintun producer can never grow memory without bound — when the
/// channel is full the newest packet is dropped and counted
/// (`backpressure_dropped`); it is never queued forever and never
/// retransmitted (retransmission is a later milestone, if ever).
pub const DATA_PLANE_CHANNEL_CAPACITY: usize = 1024;

/// Live data-plane counters. Plain atomics so the Wintun reader thread,
/// the async sender task, and the shutdown reporter can share them
/// without locking.
#[derive(Debug, Default)]
pub struct DataPlaneMetrics {
    /// Inner packets pulled from the Wintun ring by the reader thread.
    pub wintun_packets_read: AtomicU64,
    /// BondNet `Data` packets handed to the OS UDP socket.
    pub tunnel_packets_sent: AtomicU64,
    /// Wire bytes handed to the OS (`HEADER_LEN` + payload per packet).
    pub tunnel_bytes_sent: AtomicU64,
    /// UDP send failures (encode or socket). The loop keeps running.
    pub send_errors: AtomicU64,
    /// Inner packets rejected for exceeding the configured budget.
    pub oversized_dropped: AtomicU64,
    /// Empty (0-byte) inner packets rejected. Wintun never produces
    /// these; seeing one signals a bug or a corrupt handoff.
    pub invalid_dropped: AtomicU64,
    /// Packets dropped because the reader→sender channel was full.
    pub backpressure_dropped: AtomicU64,
}

/// Plain-data copy of [`DataPlaneMetrics`], for logging and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataPlaneMetricsSnapshot {
    pub wintun_packets_read: u64,
    pub tunnel_packets_sent: u64,
    pub tunnel_bytes_sent: u64,
    pub send_errors: u64,
    pub oversized_dropped: u64,
    pub invalid_dropped: u64,
    pub backpressure_dropped: u64,
}

impl DataPlaneMetrics {
    /// Read every counter.
    pub fn snapshot(&self) -> DataPlaneMetricsSnapshot {
        DataPlaneMetricsSnapshot {
            wintun_packets_read: self.wintun_packets_read.load(Ordering::Relaxed),
            tunnel_packets_sent: self.tunnel_packets_sent.load(Ordering::Relaxed),
            tunnel_bytes_sent: self.tunnel_bytes_sent.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            oversized_dropped: self.oversized_dropped.load(Ordering::Relaxed),
            invalid_dropped: self.invalid_dropped.load(Ordering::Relaxed),
            backpressure_dropped: self.backpressure_dropped.load(Ordering::Relaxed),
        }
    }
}

/// Everything that can go wrong moving one Wintun packet into the tunnel.
#[derive(Debug)]
pub enum DataPlaneError {
    /// A 0-byte "packet" arrived. Not real traffic — bug or corrupt
    /// handoff. Rejected and counted, never sent.
    EmptyPacket,
    /// Inner packet larger than the configured budget. Rejected and
    /// counted — never fragmented, never truncated.
    PacketTooLarge { len: usize, max: usize },
    /// The Day 7 transport failed (encode or UDP send). Counted as
    /// `send_errors`; the caller decides whether to continue.
    Transport(TransportError),
    /// The reader→sender channel is closed (the other end is gone).
    ChannelClosed,
    /// Shutdown was requested mid-operation.
    Shutdown,
}

impl fmt::Display for DataPlaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPacket => write!(f, "empty inner packet rejected"),
            Self::PacketTooLarge { len, max } => {
                write!(f, "inner packet too large: {len} bytes (max {max})")
            }
            Self::Transport(_) => write!(f, "tunnel transport failed"),
            Self::ChannelClosed => write!(f, "data-plane channel closed"),
            Self::Shutdown => write!(f, "data-plane shutting down"),
        }
    }
}

impl std::error::Error for DataPlaneError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

/// The Day 9 data plane: validates Wintun bytes and sends them as
/// BondNet `Data` packets over one physical `UdpPath`.
///
/// All methods take `&self` so one instance is shared between the async
/// sender task and the metrics reporter. Sequence numbers come from the
/// wrapped `UdpPath` — the BondNet tunnel sequence, not a TCP sequence,
/// not an IP identification field, not a Wintun packet number.
pub struct DataPlane {
    path: UdpPath,
    metrics: Arc<DataPlaneMetrics>,
    max_wintun_len: usize,
}

impl DataPlane {
    /// Build a data plane over `path` with the default packet budget
    /// ([`MAX_WINTUN_PACKET_LEN`]).
    pub fn new(path: UdpPath) -> Self {
        Self::with_max_wintun_len(path, MAX_WINTUN_PACKET_LEN)
    }

    /// Build a data plane over `path` with an explicit inner-packet
    /// budget. Tests use this to exercise the size gate cheaply.
    pub fn with_max_wintun_len(path: UdpPath, max_wintun_len: usize) -> Self {
        Self {
            path,
            metrics: Arc::new(DataPlaneMetrics::default()),
            max_wintun_len,
        }
    }

    /// Shared live counters.
    pub fn metrics(&self) -> &Arc<DataPlaneMetrics> {
        &self.metrics
    }

    /// Plain-data copy of the live counters.
    pub fn metrics_snapshot(&self) -> DataPlaneMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// The configured inner-packet budget in bytes.
    pub fn max_wintun_len(&self) -> usize {
        self.max_wintun_len
    }

    /// Wrap one inner Layer-3 packet as `PacketType::Data` and send it
    /// through the physical path.
    ///
    /// The payload is the exact `packet` bytes — no envelope, no IP/TCP
    /// metadata, no interface identifiers are added. Session ID, path ID
    /// and the tunnel sequence number come from the `UdpPath`
    /// configuration. Returns the BondNet tunnel sequence number stamped
    /// on the packet.
    pub async fn send_wintun_packet(&self, packet: &[u8]) -> Result<u64, DataPlaneError> {
        if packet.is_empty() {
            self.metrics.invalid_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(DataPlaneError::EmptyPacket);
        }
        if packet.len() > self.max_wintun_len {
            self.metrics
                .oversized_dropped
                .fetch_add(1, Ordering::Relaxed);
            return Err(DataPlaneError::PacketTooLarge {
                len: packet.len(),
                max: self.max_wintun_len,
            });
        }
        match self.path.send_new(PacketType::Data, packet.to_vec()).await {
            Ok(sequence) => {
                self.metrics
                    .tunnel_packets_sent
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .tunnel_bytes_sent
                    .fetch_add((HEADER_LEN + packet.len()) as u64, Ordering::Relaxed);
                Ok(sequence)
            }
            Err(error) => {
                self.metrics.send_errors.fetch_add(1, Ordering::Relaxed);
                Err(DataPlaneError::Transport(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 1024 × 1500 B ≈ 1.5 MiB worst case: bounded by construction.
    // `assertions_on_constants` is allowed here deliberately: if the
    // capacity constants ever change, this test fails loudly instead of
    // silently allowing unbounded memory.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn channel_capacity_bounds_memory() {
        assert_eq!(DATA_PLANE_CHANNEL_CAPACITY, 1024);
        assert!(DATA_PLANE_CHANNEL_CAPACITY * MAX_WINTUN_PACKET_LEN <= 2 * 1024 * 1024);
    }

    #[test]
    fn default_budget_is_1500_byte_class() {
        assert_eq!(MAX_WINTUN_PACKET_LEN, 1500);
    }

    #[test]
    fn error_display_names_sizes() {
        let error = DataPlaneError::PacketTooLarge {
            len: 1501,
            max: 1500,
        };
        assert_eq!(
            error.to_string(),
            "inner packet too large: 1501 bytes (max 1500)"
        );
        assert_eq!(
            DataPlaneError::EmptyPacket.to_string(),
            "empty inner packet rejected"
        );
        assert_eq!(
            DataPlaneError::ChannelClosed.to_string(),
            "data-plane channel closed"
        );
        assert_eq!(
            DataPlaneError::Shutdown.to_string(),
            "data-plane shutting down"
        );
    }

    #[test]
    fn metrics_start_at_zero() {
        let snapshot = DataPlaneMetrics::default().snapshot();
        assert_eq!(snapshot, DataPlaneMetricsSnapshot::default());
    }
}
