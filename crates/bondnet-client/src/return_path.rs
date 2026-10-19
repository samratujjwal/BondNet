//! Day 11 return path: UDP → decode → validate → Wintun.
//!
//! ```text
//! UDP datagram (from the VPS)
//!   → Packet::decode()          (bondnet-protocol is the single wire truth)
//!   → PacketType::Data          (any other type is rejected, counted)
//!   → session/path check        (must match this client's association)
//!   → validate_ip_packet()      (structural IPv4/IPv6 check, no panics)
//!   → Wintun send ring          (exact payload bytes, via WintunWriter)
//!   → Windows IP stack
//! ```
//!
//! Direction is by arrival interface: datagrams arriving on the UDP
//! socket are return traffic; packets read from Wintun are upload
//! traffic. A return packet is never fed back into the upload
//! [`DataPlane`](crate::data_plane::DataPlane), so it cannot loop.
//!
//! # Plaintext warning
//!
//! Like the rest of BondNet so far, return traffic is unencrypted and
//! the session/path check is NOT authentication — anyone who can send
//! UDP to this socket can inject packets that pass the check. Development
//! use only.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bondnet_protocol::{Packet, PacketType, validate_ip_packet};

use crate::wintun::WintunError;

/// Bounded handoff between the async UDP receiver task and the Wintun
/// writer thread: 1024 packets × 1500 bytes ≈ 1.5 MiB worst case. When
/// full the newest packet is dropped and counted
/// (`backpressure_dropped`); memory never grows without bound.
pub const RETURN_CHANNEL_CAPACITY: usize = 1024;

/// Day 15: maximum out-of-order return packets buffered before Wintun
/// delivery. Bounds memory; overflow is dropped and counted.
pub const RETURN_REORDER_BUFFER_SIZE: usize = 256;

/// Day 15: how long a gap in the return sequence may persist before the
/// reorder buffer skips it (abandoning the missing sequences as loss).
pub const RETURN_REORDER_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(200);

/// Live return-path counters. Plain atomics so the UDP receiver task, the
/// Wintun writer thread, and the shutdown reporter can share them without
/// locking.
#[derive(Debug, Default)]
pub struct ReturnMetrics {
    /// Return `Data` packets that passed every check.
    pub packets_received: AtomicU64,
    /// Sum of validated return payload lengths in bytes.
    pub bytes_received: AtomicU64,
    /// Validated packets written into the Wintun send ring.
    pub wintun_packets_written: AtomicU64,
    /// Sum of bytes written into Wintun.
    pub wintun_bytes_written: AtomicU64,
    /// Datagrams that failed decode or were not `Data`.
    pub invalid_protocol: AtomicU64,
    /// `Data` packets with the wrong session or path ID.
    pub invalid_session_path: AtomicU64,
    /// `Data` payloads that failed IP validation.
    pub invalid_ip: AtomicU64,
    /// Wintun send failures (ring full or allocation error).
    pub wintun_write_errors: AtomicU64,
    /// Validated packets dropped because the UDP→Wintun channel was full.
    pub backpressure_dropped: AtomicU64,
}

/// Plain-data copy of [`ReturnMetrics`], for logging and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReturnMetricsSnapshot {
    pub packets_received: u64,
    pub bytes_received: u64,
    pub wintun_packets_written: u64,
    pub wintun_bytes_written: u64,
    pub invalid_protocol: u64,
    pub invalid_session_path: u64,
    pub invalid_ip: u64,
    pub wintun_write_errors: u64,
    pub backpressure_dropped: u64,
}

impl ReturnMetrics {
    /// Read every counter.
    pub fn snapshot(&self) -> ReturnMetricsSnapshot {
        ReturnMetricsSnapshot {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            wintun_packets_written: self.wintun_packets_written.load(Ordering::Relaxed),
            wintun_bytes_written: self.wintun_bytes_written.load(Ordering::Relaxed),
            invalid_protocol: self.invalid_protocol.load(Ordering::Relaxed),
            invalid_session_path: self.invalid_session_path.load(Ordering::Relaxed),
            invalid_ip: self.invalid_ip.load(Ordering::Relaxed),
            wintun_write_errors: self.wintun_write_errors.load(Ordering::Relaxed),
            backpressure_dropped: self.backpressure_dropped.load(Ordering::Relaxed),
        }
    }
}

/// Everything that can go wrong validating one return packet.
#[derive(Debug)]
pub enum ReturnError {
    /// Not a `Data` packet (wrong type; decode failures are reported by
    /// the transport before this runs).
    WrongType(PacketType),
    /// Session ID does not match this client's.
    WrongSession { expected: u64, got: u64 },
    /// Path ID does not match this client's.
    WrongPath { expected: u16, got: u16 },
    /// Inner IP packet failed structural validation.
    InvalidIp(bondnet_protocol::IpRejectReason),
    /// The Wintun write failed.
    WintunWrite(WintunError),
}

impl fmt::Display for ReturnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongType(t) => write!(f, "return packet has wrong type {t:?}"),
            Self::WrongSession { expected, got } => {
                write!(f, "return packet session {got} != {expected}")
            }
            Self::WrongPath { expected, got } => {
                write!(f, "return packet path {got} != {expected}")
            }
            Self::InvalidIp(reason) => write!(f, "return packet invalid IP: {reason}"),
            Self::WintunWrite(error) => write!(f, "wintun write failed: {error}"),
        }
    }
}

impl std::error::Error for ReturnError {}

/// Abstraction over writing IP packets into the virtual adapter.
///
/// Implemented by [`WintunSession`](crate::wintun::WintunSession) on
/// Windows; tests use a fake, so no real adapter is ever needed.
pub trait WintunWriter {
    /// Write exactly one validated IP packet into the adapter.
    fn write_ip_packet(&mut self, packet: &[u8]) -> Result<(), WintunError>;
}

#[cfg(windows)]
impl WintunWriter for crate::wintun::WintunSession<'_> {
    fn write_ip_packet(&mut self, packet: &[u8]) -> Result<(), WintunError> {
        self.send_packet(packet)
    }
}

/// Validates inbound UDP packets for the return path.
///
/// Pure: takes a decoded [`Packet`], checks type/session/path/IP, and
/// returns the payload bytes on success. The caller owns the Wintun write
/// (via [`WintunWriter`]) and the metrics live here so both the async
/// receiver and the writer thread can count without locking.
pub struct ReturnProcessor {
    session_id: u64,
    path_id: u16,
    metrics: Arc<ReturnMetrics>,
    /// Day 19: optional secure session for decrypting return DATA.
    secure_session: std::sync::Mutex<Option<std::sync::Arc<bondnet_crypto::SecureSession>>>,
}

impl ReturnProcessor {
    /// Build a processor for this client's `(session_id, path_id)`.
    pub fn new(session_id: u64, path_id: u16) -> Self {
        Self::with_metrics(session_id, path_id, Arc::new(ReturnMetrics::default()))
    }

    /// Build a processor sharing an existing metrics handle, so a spawned
    /// task and its owner can report from the same counters.
    pub fn with_metrics(session_id: u64, path_id: u16, metrics: Arc<ReturnMetrics>) -> Self {
        Self {
            session_id,
            path_id,
            metrics,
            secure_session: std::sync::Mutex::new(None),
        }
    }

    /// Day 19: attach a secure session for decrypting return DATA.
    pub fn set_secure_session(&self, session: std::sync::Arc<bondnet_crypto::SecureSession>) {
        *self.secure_session.lock().expect("secure lock poisoned") = Some(session);
    }

    /// Shared live counters.
    pub fn metrics(&self) -> &Arc<ReturnMetrics> {
        &self.metrics
    }

    /// Plain-data copy of the live counters.
    pub fn metrics_snapshot(&self) -> ReturnMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Validate one decoded inbound packet.
    ///
    /// Returns the inner IP payload bytes (borrowed from the packet) when
    /// every check passes. Never panics on any input; every rejection is
    /// counted.
    pub fn validate<'a>(&self, packet: &'a Packet) -> Result<&'a [u8], ReturnError> {
        let h = &packet.header;
        if h.packet_type != PacketType::Data {
            self.metrics
                .invalid_protocol
                .fetch_add(1, Ordering::Relaxed);
            return Err(ReturnError::WrongType(h.packet_type));
        }
        if h.session_id != self.session_id {
            self.metrics
                .invalid_session_path
                .fetch_add(1, Ordering::Relaxed);
            return Err(ReturnError::WrongSession {
                expected: self.session_id,
                got: h.session_id,
            });
        }
        if h.path_id != self.path_id {
            self.metrics
                .invalid_session_path
                .fetch_add(1, Ordering::Relaxed);
            return Err(ReturnError::WrongPath {
                expected: self.path_id,
                got: h.path_id,
            });
        }
        if let Err(reason) = validate_ip_packet(&packet.payload) {
            self.metrics.invalid_ip.fetch_add(1, Ordering::Relaxed);
            return Err(ReturnError::InvalidIp(reason));
        }
        self.metrics
            .packets_received
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_received
            .fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
        Ok(&packet.payload)
    }

    /// Day 19: validate and decrypt a packet (if secure session is set).
    ///
    /// Returns the decrypted IP payload as an owned Vec. If no secure
    /// session is set, behaves like `validate` (returns borrowed data
    /// as owned).
    pub fn validate_decrypted(
        &self,
        packet: &Packet,
        datagram: &[u8],
    ) -> Result<Vec<u8>, ReturnError> {
        // First, check the header fields (without payload validation).
        let h = &packet.header;
        if h.packet_type != PacketType::Data {
            self.metrics
                .invalid_protocol
                .fetch_add(1, Ordering::Relaxed);
            return Err(ReturnError::WrongType(h.packet_type));
        }
        if h.session_id != self.session_id {
            self.metrics
                .invalid_session_path
                .fetch_add(1, Ordering::Relaxed);
            return Err(ReturnError::WrongSession {
                expected: self.session_id,
                got: h.session_id,
            });
        }
        if h.path_id != self.path_id {
            self.metrics
                .invalid_session_path
                .fetch_add(1, Ordering::Relaxed);
            return Err(ReturnError::WrongPath {
                expected: self.path_id,
                got: h.path_id,
            });
        }

        // Decrypt if a secure session is set.
        let payload = if let Some(session) = self
            .secure_session
            .lock()
            .expect("secure lock poisoned")
            .as_ref()
        {
            // AAD is the 36-byte header from the datagram.
            if datagram.len() < 36 {
                self.metrics
                    .invalid_protocol
                    .fetch_add(1, Ordering::Relaxed);
                return Err(ReturnError::WrongType(h.packet_type));
            }
            let mut aad = [0u8; 36];
            aad.copy_from_slice(&datagram[..36]);
            // Use ReturnData domain with sequence as counter.
            match session.decrypt(
                bondnet_crypto::KeyDomain::ReturnData,
                h.sequence,
                &aad,
                &packet.payload,
            ) {
                Ok(pt) => pt,
                Err(_) => {
                    self.metrics
                        .invalid_protocol
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(ReturnError::WrongType(h.packet_type)); // Reuse error type
                }
            }
        } else {
            packet.payload.clone()
        };

        // Validate the (decrypted) IP payload.
        if let Err(reason) = validate_ip_packet(&payload) {
            self.metrics.invalid_ip.fetch_add(1, Ordering::Relaxed);
            return Err(ReturnError::InvalidIp(reason));
        }
        self.metrics
            .packets_received
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_received
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        Ok(payload)
    }

    /// Validate one packet and write it through `writer`.
    ///
    /// Counts `wintun_packets_written`/`wintun_bytes_written` on success
    /// and `wintun_write_errors` on failure. Used by the Wintun writer
    /// thread; unit-tested with a fake writer on every platform.
    pub fn validate_and_write<W: WintunWriter>(
        &self,
        packet: &Packet,
        writer: &mut W,
    ) -> Result<(), ReturnError> {
        let payload = self.validate(packet)?;
        writer.write_ip_packet(payload).map_err(|error| {
            self.metrics
                .wintun_write_errors
                .fetch_add(1, Ordering::Relaxed);
            ReturnError::WintunWrite(error)
        })?;
        self.metrics
            .wintun_packets_written
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .wintun_bytes_written
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bondnet_protocol::{PROTOCOL_VERSION, PacketHeader};

    fn packet(session_id: u64, path_id: u16, packet_type: PacketType, payload: Vec<u8>) -> Packet {
        Packet {
            header: PacketHeader {
                version: PROTOCOL_VERSION,
                flags: 0,
                session_id,
                sequence: 1,
                path_id,
                packet_type,
                timestamp: 1_700_000_000_000,
            },
            payload,
        }
    }

    /// Minimal valid IPv4 packet: 20-byte header, IHL=5, total=20.
    fn ipv4_min() -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&20u16.to_be_bytes());
        p
    }

    /// A fake Wintun writer: records bytes, optionally fails.
    #[derive(Debug, Default)]
    struct FakeWriter {
        written: Vec<Vec<u8>>,
        fail: bool,
    }

    impl WintunWriter for FakeWriter {
        fn write_ip_packet(&mut self, packet: &[u8]) -> Result<(), WintunError> {
            if self.fail {
                return Err(WintunError::SendBufferFull);
            }
            self.written.push(packet.to_vec());
            Ok(())
        }
    }

    #[test]
    fn valid_data_packet_validates_and_writes_unchanged() {
        let processor = ReturnProcessor::new(1001, 1);
        let payload = ipv4_min();
        let pkt = packet(1001, 1, PacketType::Data, payload.clone());
        let mut writer = FakeWriter::default();
        processor.validate_and_write(&pkt, &mut writer).unwrap();
        assert_eq!(writer.written, vec![payload]);
        let m = processor.metrics_snapshot();
        assert_eq!(m.packets_received, 1);
        assert_eq!(m.bytes_received, 20);
        assert_eq!(m.wintun_packets_written, 1);
        assert_eq!(m.wintun_bytes_written, 20);
    }

    #[test]
    fn wrong_packet_type_rejected() {
        let processor = ReturnProcessor::new(1001, 1);
        let pkt = packet(1001, 1, PacketType::PathHello, ipv4_min());
        let mut writer = FakeWriter::default();
        let err = processor.validate_and_write(&pkt, &mut writer).unwrap_err();
        assert!(matches!(err, ReturnError::WrongType(PacketType::PathHello)));
        assert!(writer.written.is_empty());
        assert_eq!(processor.metrics_snapshot().invalid_protocol, 1);
    }

    #[test]
    fn wrong_session_rejected() {
        let processor = ReturnProcessor::new(1001, 1);
        let pkt = packet(9999, 1, PacketType::Data, ipv4_min());
        let mut writer = FakeWriter::default();
        let err = processor.validate_and_write(&pkt, &mut writer).unwrap_err();
        assert!(matches!(
            err,
            ReturnError::WrongSession {
                expected: 1001,
                got: 9999
            }
        ));
        assert!(writer.written.is_empty());
        assert_eq!(processor.metrics_snapshot().invalid_session_path, 1);
    }

    #[test]
    fn wrong_path_rejected() {
        let processor = ReturnProcessor::new(1001, 1);
        let pkt = packet(1001, 2, PacketType::Data, ipv4_min());
        let mut writer = FakeWriter::default();
        let err = processor.validate_and_write(&pkt, &mut writer).unwrap_err();
        assert!(matches!(
            err,
            ReturnError::WrongPath {
                expected: 1,
                got: 2
            }
        ));
        assert!(writer.written.is_empty());
        assert_eq!(processor.metrics_snapshot().invalid_session_path, 1);
    }

    #[test]
    fn invalid_ipv4_payload_rejected() {
        let processor = ReturnProcessor::new(1001, 1);
        // 20 zero bytes: version nibble 0.
        let pkt = packet(1001, 1, PacketType::Data, vec![0u8; 20]);
        let mut writer = FakeWriter::default();
        let err = processor.validate_and_write(&pkt, &mut writer).unwrap_err();
        assert!(matches!(err, ReturnError::InvalidIp(_)));
        assert!(writer.written.is_empty());
        let m = processor.metrics_snapshot();
        assert_eq!(m.invalid_ip, 1);
        assert_eq!(m.packets_received, 0);
    }

    #[test]
    fn invalid_ipv6_payload_rejected() {
        let processor = ReturnProcessor::new(1001, 1);
        // Version 6 but truncated (30 < 40).
        let pkt = packet(1001, 1, PacketType::Data, vec![0x60u8; 30]);
        let mut writer = FakeWriter::default();
        assert!(processor.validate_and_write(&pkt, &mut writer).is_err());
        assert_eq!(processor.metrics_snapshot().invalid_ip, 1);
    }

    #[test]
    fn valid_ipv6_packet_accepted() {
        let processor = ReturnProcessor::new(1001, 1);
        let mut payload = vec![0u8; 40];
        payload[0] = 0x60;
        let pkt = packet(1001, 1, PacketType::Data, payload.clone());
        let mut writer = FakeWriter::default();
        processor.validate_and_write(&pkt, &mut writer).unwrap();
        assert_eq!(writer.written, vec![payload]);
    }

    #[test]
    fn wintun_write_failure_reported_safely() {
        let processor = ReturnProcessor::new(1001, 1);
        let pkt = packet(1001, 1, PacketType::Data, ipv4_min());
        let mut writer = FakeWriter {
            fail: true,
            ..Default::default()
        };
        let err = processor.validate_and_write(&pkt, &mut writer).unwrap_err();
        assert!(matches!(err, ReturnError::WintunWrite(_)));
        // Validation passed (counted), the write failed (counted).
        let m = processor.metrics_snapshot();
        assert_eq!(m.packets_received, 1);
        assert_eq!(m.wintun_write_errors, 1);
        assert_eq!(m.wintun_packets_written, 0);
    }

    #[test]
    fn error_display_names_causes() {
        assert!(
            ReturnError::WrongType(PacketType::Data)
                .to_string()
                .contains("wrong type")
        );
        assert!(
            ReturnError::WrongSession {
                expected: 1,
                got: 2
            }
            .to_string()
            .contains("session")
        );
    }

    #[test]
    fn metrics_start_at_zero() {
        assert_eq!(
            ReturnMetrics::default().snapshot(),
            ReturnMetricsSnapshot::default()
        );
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn channel_capacity_bounds_memory() {
        assert_eq!(RETURN_CHANNEL_CAPACITY, 1024);
        assert!(RETURN_CHANNEL_CAPACITY * 1500 <= 2 * 1024 * 1024);
    }
}
