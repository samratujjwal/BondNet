//! BondNet wire protocol.
//!
//! Owns the on-the-wire packet format: header layout, packet types, encoding,
//! decoding, and validation. It deliberately knows nothing about sockets,
//! platform APIs, encryption, or scheduling, so the protocol can evolve and be
//! tested independently of how packets are transported.
