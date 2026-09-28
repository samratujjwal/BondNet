//! BondNet platform-independent engine.
//!
//! Will own the tunnel session, packet sequencing, the reorder buffer, path
//! state, and the state machine gluing protocol, crypto, and scheduler
//! together. It depends on the three leaf crates but never on platform code,
//! so the same core drives both the Windows client and the Linux server.
//! Day 1: scaffold only, no tunnel logic implemented yet.
//!
//! Day 5: reorder buffer implemented ([`reorder`]) — a deterministic,
//! dependency-free data structure that turns out-of-order tunnel sequences
//! into an in-order stream. No networking, no timers, no retransmission.

pub mod reorder;

pub use reorder::{GapInfo, PushResult, ReorderBuffer};
