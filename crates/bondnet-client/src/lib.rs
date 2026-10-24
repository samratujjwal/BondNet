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

pub mod bench;
pub mod config;
pub mod data_plane;
pub mod error;
pub mod health;
pub mod health_diag;
pub mod health_monitor;
pub mod multipath;
pub mod path_manager;
pub mod return_path;
pub mod synthetic;
pub mod transport;
pub mod wintun;

pub use config::{
    DEFAULT_BANDWIDTH_BPS, PhysicalPathConfig, UdpPathConfig, parse_args, parse_psk_hex,
    validate_path_configs,
};
pub use data_plane::{
    DATA_PLANE_CHANNEL_CAPACITY, DataPlane, DataPlaneError, DataPlaneMetrics,
    DataPlaneMetricsSnapshot, MAX_WINTUN_PACKET_LEN,
};
pub use error::TransportError;
pub use multipath::{
    MultipathDataPlane, MultipathError, MultipathMetrics, MultipathMetricsSnapshot,
};
pub use path_manager::{ManagedPath, PathManager, PathStatus};
pub use return_path::{
    RETURN_CHANNEL_CAPACITY, ReturnError, ReturnMetrics, ReturnMetricsSnapshot, ReturnProcessor,
    WintunWriter,
};
pub use synthetic::{ipv4_checksum_valid, ipv4_udp_test_packet};
pub use transport::{PathStatsSnapshot, UdpPath};
