//! Crypto error type.

use thiserror::Error;

/// Failures when constructing keys/nonces or performing AEAD.
///
/// Authentication failure is deliberately distinct from API misuse: a bad
/// ciphertext, tag, key, nonce, or AAD yields
/// [`CryptoError::AuthenticationFailed`], while malformed inputs to the API
/// itself yield the `Invalid*` variants. No message leaks cryptographic
/// internals, and decrypting attacker-controlled bytes never panics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CryptoError {
    /// Key material is not exactly [`crate::KEY_SIZE`] bytes.
    #[error("invalid key length: expected 32 bytes")]
    InvalidKeyLength,
    /// Nonce is not exactly [`crate::NONCE_SIZE`] bytes.
    #[error("invalid nonce length: expected 24 bytes")]
    InvalidNonceLength,
    /// Ciphertext, tag, key, nonce, or AAD did not authenticate.
    /// No plaintext is returned in this case.
    #[error("authentication failed")]
    AuthenticationFailed,
}
