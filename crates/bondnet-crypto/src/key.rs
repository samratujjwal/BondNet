//! Strongly-typed key and nonce wrappers.
//!
//! Fixed-size arrays make wrong key/nonce lengths unrepresentable at the call
//! site. [`CryptoKey::from_slice`] and [`Nonce::from_slice`] convert
//! variable-length input into these types with a typed error instead of a
//! panic.

use std::fmt;
use zeroize::Zeroize;

use crate::constants::{KEY_SIZE, NONCE_SIZE};
use crate::error::CryptoError;

/// A 256-bit symmetric encryption key.
///
/// The key bytes are zeroized on drop. This is best-effort hygiene against
/// key material lingering in freed memory; it does not protect against swap
/// files, core dumps, or memory-disclosure bugs. Only the key — the actual
/// secret — is zeroized; nonces are public values and need no such treatment.
///
/// `Debug` is redacted on purpose: key bytes must never appear in logs.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct CryptoKey([u8; KEY_SIZE]);

impl CryptoKey {
    /// Build a key from raw bytes. Fails with [`CryptoError::InvalidKeyLength`]
    /// unless `bytes` is exactly 32 bytes — never panics.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        Ok(CryptoKey(arr))
    }

    /// Borrow the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

impl fmt::Debug for CryptoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CryptoKey([redacted])")
    }
}

/// A 24-byte XChaCha nonce.
///
/// Explicitly caller-supplied: the crypto crate never generates nonces itself,
/// so the future BondNet session layer keeps deterministic, auditable control
/// over nonce assignment. Nonce uniqueness per key is the caller's
/// responsibility and is enforced there, not inside this primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce([u8; NONCE_SIZE]);

impl Nonce {
    /// Build a nonce from raw bytes. Fails with
    /// [`CryptoError::InvalidNonceLength`] unless `bytes` is exactly 24
    /// bytes — never panics.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; NONCE_SIZE] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidNonceLength)?;
        Ok(Nonce(arr))
    }

    /// Borrow the raw nonce bytes.
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.0
    }
}
