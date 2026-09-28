//! Crypto constants: key, nonce, and tag sizes.
//!
//! These sizes are dictated by XChaCha20-Poly1305 and the BondNet key plan;
//! they are not tunable.

/// 256-bit symmetric key.
pub const KEY_SIZE: usize = 32;

/// XChaCha20 nonce: 24 bytes. The large nonce space is why XChaCha (and not
/// plain ChaCha20-Poly1305 with its 12-byte nonce) was chosen: it leaves room
/// for the future session layer to derive per-packet nonces deterministically
/// without collision risk.
pub const NONCE_SIZE: usize = 24;

/// Poly1305 authentication tag appended to every ciphertext.
pub const TAG_SIZE: usize = 16;
