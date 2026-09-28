//! Protocol constants: magic, version, header size, payload limits.
//!
//! These values are wire-compatibility commitments. Do not change them
//! casually; a change needs a protocol versioning proposal instead.

/// Two-byte protocol marker: ASCII `"BN"` (`0x42 0x4E`).
/// The decoder rejects any packet whose first two bytes differ.
pub const MAGIC: [u8; 2] = [0x42, 0x4E];

/// Current protocol version. The decoder rejects anything else.
pub const PROTOCOL_VERSION: u8 = 1;

/// Fixed header size in bytes.
/// Layout: magic(2) + version(1) + flags(1) + header_len(2) + session_id(8)
/// + sequence(8) + path_id(2) + packet_type(1) + reserved(1) + timestamp(8)
/// + payload_len(2) = 36.
pub const HEADER_LEN: usize = 36;

/// Largest payload the `u16` payload-length field can describe (65535 bytes).
/// This is a protocol-format limit, NOT the network/tunnel MTU — the real
/// MTU/MSS design happens later with Wintun and VPS forwarding.
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;
