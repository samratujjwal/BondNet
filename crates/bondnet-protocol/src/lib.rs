//! BondNet wire protocol.
//!
//! Owns the on-the-wire packet format: header layout, packet types, encoding,
//! decoding, and validation. It deliberately knows nothing about sockets,
//! platform APIs, encryption, or scheduling, so the protocol can evolve and be
//! tested independently of how packets are transported.
//!
//! All integers are big-endian (network byte order). The fixed header is
//! [`HEADER_LEN`] bytes; see [`constants`] for the exact layout.

pub mod codec;
pub mod constants;
pub mod error;
pub mod ip;
pub mod packet;

pub use constants::{HEADER_LEN, MAGIC, MAX_PAYLOAD_LEN, PROTOCOL_VERSION};
pub use error::ProtocolError;
pub use ip::{IpRejectReason, IpVersion, validate_ip_packet};
pub use packet::{Packet, PacketHeader, PacketType};
