//! XChaCha20-Poly1305 authenticated encryption.
//!
//! All cryptography is delegated to the maintained `chacha20poly1305` crate
//! (RustCrypto). Nothing here implements a cipher, a MAC, or an AEAD
//! construction by hand.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use crate::error::CryptoError;
use crate::key::{CryptoKey, Nonce};

fn cipher(key: &CryptoKey) -> XChaCha20Poly1305 {
    // `CryptoKey` is always exactly 32 bytes by construction, so key setup
    // cannot fail here.
    XChaCha20Poly1305::new(&Key::from(*key.as_bytes()))
}

/// Encrypt `plaintext` with `key` and `nonce`, authenticating `aad`.
///
/// Returns `ciphertext || tag`: the encrypted plaintext followed by the
/// 16-byte Poly1305 authentication tag, exactly as the underlying AEAD
/// produces it. `aad` is authenticated but NOT encrypted.
///
/// The nonce is caller-supplied and must never repeat for a given key; nonce
/// lifecycle belongs to the future BondNet session layer.
pub fn encrypt(
    key: &CryptoKey,
    nonce: &Nonce,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    cipher(key)
        .encrypt(
            &XNonce::from(*nonce.as_bytes()),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        // Encryption with a valid key/nonce is infallible in practice; the
        // error arm exists only to keep the API total without exposing
        // low-level internals.
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Decrypt `ciphertext` (ciphertext || tag) with `key` and `nonce`, verifying
/// `aad`.
///
/// Returns the plaintext only if the tag verifies. Any modification of the
/// ciphertext, tag, key, nonce, or AAD fails with
/// [`CryptoError::AuthenticationFailed`] and yields no plaintext.
/// Never panics on attacker-controlled input.
pub fn decrypt(
    key: &CryptoKey,
    nonce: &Nonce,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    cipher(key)
        .decrypt(
            &XNonce::from(*nonce.as_bytes()),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}
