//! Protocol error type.

use std::fmt;

/// Failures when encoding or decoding BondNet packets.
///
/// Decoding untrusted bytes never panics; every malformed input maps to one
/// of these variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// First two bytes are not the `"BN"` magic marker.
    InvalidMagic,
    /// Version byte is not [`crate::PROTOCOL_VERSION`].
    UnsupportedVersion { found: u8 },
    /// Header-length field does not equal [`crate::HEADER_LEN`].
    InvalidHeaderLength { found: u16 },
    /// Flags byte has unknown/reserved bits set (v1 requires zero).
    InvalidFlags { found: u8 },
    /// Reserved byte is non-zero.
    InvalidReservedField { found: u8 },
    /// Packet-type byte is not a known [`crate::PacketType`].
    UnknownPacketType { found: u8 },
    /// Input is shorter than the fixed header.
    PacketTooShort { len: usize },
    /// Total input length does not equal header + declared payload length.
    /// Covers truncated packets, lying length fields, and trailing bytes.
    PayloadLengthMismatch { declared: usize, actual: usize },
    /// Payload exceeds [`crate::MAX_PAYLOAD_LEN`] (encode side).
    PayloadTooLarge { len: usize },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::InvalidMagic => write!(f, "invalid magic marker"),
            ProtocolError::UnsupportedVersion { found } => {
                write!(f, "unsupported protocol version: {found}")
            }
            ProtocolError::InvalidHeaderLength { found } => {
                write!(f, "invalid header length: {found}")
            }
            ProtocolError::InvalidFlags { found } => {
                write!(f, "unknown flag bits set: {found:#04x}")
            }
            ProtocolError::InvalidReservedField { found } => {
                write!(f, "reserved field must be zero, found: {found:#04x}")
            }
            ProtocolError::UnknownPacketType { found } => {
                write!(f, "unknown packet type: {found}")
            }
            ProtocolError::PacketTooShort { len } => {
                write!(f, "packet too short: {len} bytes")
            }
            ProtocolError::PayloadLengthMismatch { declared, actual } => write!(
                f,
                "payload length mismatch: declared {declared}, actual {actual}"
            ),
            ProtocolError::PayloadTooLarge { len } => {
                write!(f, "payload too large: {len} bytes")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}
