//! BondNet cryptographic primitives.
//!
//! Will own authenticated encryption, nonce handling, key management, and
//! replay-protection helpers. Kept separate from the protocol crate so packet
//! framing never depends on cryptographic details, and separate from core so
//! the crypto can be audited and tested in isolation.
//! Day 1: scaffold only, no cryptography implemented yet.
