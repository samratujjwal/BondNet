//! BondNet Windows client.
//!
//! Day 7: a client-side UDP transport abstraction (`UdpPath`) that binds a
//! socket to one explicit local IPv4 address — the physical path the OS
//! will route through — and sends valid BondNet protocol packets to the
//! VPS. One path only; no Wintun, no bonding, no encryption yet.
//!
//! Day 9: a thin data plane (`DataPlane`) that wraps Wintun Layer-3 bytes
//! in the existing `PacketType::Data` envelope and sends them through the
//! Day 7 `UdpPath`. Payload bytes are never modified.
//!
//! # Plaintext warning
//!
//! Like the Day 6 server, this transport is intentionally unencrypted.
//! Development use only — do not send secrets or sensitive data through it.

pub mod config;
pub mod data_plane;
pub mod error;
pub mod synthetic;
pub mod transport;
pub mod wintun;

pub use config::{UdpPathConfig, parse_args};
pub use data_plane::{
    DATA_PLANE_CHANNEL_CAPACITY, DataPlane, DataPlaneError, DataPlaneMetrics,
    DataPlaneMetricsSnapshot, MAX_WINTUN_PACKET_LEN,
};
pub use error::TransportError;
pub use synthetic::{ipv4_checksum_valid, ipv4_udp_test_packet};
pub use transport::{PathStatsSnapshot, UdpPath};
