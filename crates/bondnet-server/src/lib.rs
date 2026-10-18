//! BondNet Linux VPS server.
//!
//! Day 6: a real UDP listener that receives BondNet protocol datagrams,
//! decodes them with `bondnet-protocol`, tracks observed sessions/paths,
//! and records basic telemetry. Receive/validate/telemetry only.
//!
//! Day 9: `Data` packets get their own counters (`data_packets`,
//! `data_bytes`) and a one-line `DATA_RX` verbose log with a test-only
//! payload fingerprint. Still no forwarding of any kind.
//!
//! Day 10: opt-in Linux TUN forwarding (`--tun-name`). Validated `Data`
//! payloads — exactly one well-formed IPv4/IPv6 packet each — are queued
//! (bounded, 1024) to a dedicated writer thread that performs one
//! `write(2)` per packet into a layer-3 TUN device (`IFF_TUN |
//! IFF_NO_PI`, never TAP, never persistent). The kernel then routes the
//! packet; NAT/masquerade and forwarding stay explicit administrator
//! commands (see `docs/vps-day10-setup.md` and `--print-setup`).
//!
//! # Explicitly NOT a production VPN server
//!
//! Traffic is still **plaintext**: crypto integration is scheduled
//! separately, so there is no encryption, no authentication, no key
//! exchange, and no replay protection yet. This is a development
//! networking component. Do not deploy it as a secure tunnel endpoint.
//!
//! Also not implemented: Internet return path, bonding, reordering,
//! retransmission, ACK generation, or scheduler integration.

pub mod config;
pub mod server;
pub mod tun;

pub use config::{ServerConfig, parse_args};
pub use server::{PathSnapshot, RECV_BUF_LEN, Server, ServerStats, SessionSnapshot, StatsSnapshot};
pub use tun::{
    IpRejectReason, IpVersion, TunConfig, TunConfigError, TunDevice, TunError, print_setup_guide,
    validate_ip_packet,
};
