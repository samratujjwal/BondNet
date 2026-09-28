//! BondNet Linux VPS server.
//!
//! Day 6: a development UDP server that binds one address, decodes every
//! datagram through the existing `bondnet_protocol::Packet::decode`, tracks
//! observed `(session_id, path_id)` pairs in an in-memory registry, and
//! exposes atomic counters. Malformed input is counted and logged, never
//! fatal; no ACK is ever generated.
//!
//! Day 9: the server also counts `PacketType::Data` datagrams
//! (`data_packets`/`data_bytes`) and, with `--verbose`, logs one
//! `DATA_RX` line per Data packet with a test-only fingerprint so the
//! tunnel smoke test can confirm byte-exact delivery. It forwards
//! nothing.
//!
//! # Plaintext warning
//!
//! This server is intentionally unencrypted. Development use only — a
//! development networking component, NOT a production VPN server.

pub mod config;
pub mod server;

pub use config::ServerConfig;
pub use server::{PathSnapshot, Server, ServerStats, SessionSnapshot, StatsSnapshot, RECV_BUF_LEN};
