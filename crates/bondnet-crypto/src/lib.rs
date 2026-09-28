//! BondNet authenticated encryption.
//!
//! Owns the AEAD primitive: XChaCha20-Poly1305 encryption and decryption over
//! caller-supplied keys, nonces, and associated data. It knows nothing about
//! sockets, sessions, or packet framing; key exchange, handshakes, and nonce
//! lifecycle belong to later BondNet layers.
//!
//! Intended future relationship with the Day 2 packet format:
//!
//! ```text
//! BondNet packet header
//!         ↓
//! serialized header = AAD
//!         ↓
//! encrypted payload
//!         ↓
//! ciphertext + authentication tag
//! ```
//!
//! The header stays visible for routing and validation while the payload is
//! confidential and authenticated. Day 3 does NOT wire this into
//! `bondnet-protocol`; it only proves the standalone primitive.

pub mod aead;
pub mod constants;
pub mod error;
pub mod key;

pub use aead::{decrypt, encrypt};
pub use constants::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};
pub use error::CryptoError;
pub use key::{CryptoKey, Nonce};
