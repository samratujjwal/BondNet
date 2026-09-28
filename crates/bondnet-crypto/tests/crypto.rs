//! Day 3 crypto tests: round trips, authentication failures, boundaries,
//! and a cross-checked test vector. Everything here exercises only the public API.

use bondnet_crypto::{CryptoError, CryptoKey, Nonce, TAG_SIZE, decrypt, encrypt};

fn test_key() -> CryptoKey {
    CryptoKey::from_slice(&[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ])
    .unwrap()
}

fn test_nonce() -> Nonce {
    Nonce::from_slice(&[
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    ])
    .unwrap()
}

fn other_key() -> CryptoKey {
    CryptoKey::from_slice(&[0xFF; 32]).unwrap()
}

fn other_nonce() -> Nonce {
    Nonce::from_slice(&[0x55; 24]).unwrap()
}

const AAD: &[u8] = b"BondNet/Day3/TestAAD";

#[test]
fn round_trip_basic() {
    let key = test_key();
    let nonce = test_nonce();
    let plaintext = b"bondnet tunnels ride on encrypted UDP";
    let ciphertext = encrypt(&key, &nonce, plaintext, AAD).unwrap();
    // Ciphertext is plaintext length plus the 16-byte authentication tag.
    assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);
    let recovered = decrypt(&key, &nonce, &ciphertext, AAD).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn empty_plaintext_round_trip() {
    let key = test_key();
    let nonce = test_nonce();
    let ciphertext = encrypt(&key, &nonce, &[], AAD).unwrap();
    assert_eq!(ciphertext.len(), TAG_SIZE);
    let recovered = decrypt(&key, &nonce, &ciphertext, AAD).unwrap();
    assert!(recovered.is_empty());
}

#[test]
fn empty_aad_round_trip() {
    let key = test_key();
    let nonce = test_nonce();
    let plaintext = b"aad is optional";
    let ciphertext = encrypt(&key, &nonce, plaintext, &[]).unwrap();
    let recovered = decrypt(&key, &nonce, &ciphertext, &[]).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn binary_payload_preserved() {
    let key = test_key();
    let nonce = test_nonce();
    let mut plaintext: Vec<u8> = (0u8..=255u8).collect();
    plaintext.extend_from_slice(&[0x00, 0xFF, 0x01, 0x80, 0x00, 0xFF]);
    assert!(plaintext.windows(2).any(|w| w == [0x00, 0xFF]));
    let recovered = decrypt(
        &key,
        &nonce,
        &encrypt(&key, &nonce, &plaintext, AAD).unwrap(),
        AAD,
    )
    .unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn large_payload_64kib_round_trip() {
    let key = test_key();
    let nonce = test_nonce();
    let plaintext: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    let ciphertext = encrypt(&key, &nonce, &plaintext, AAD).unwrap();
    assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);
    let recovered = decrypt(&key, &nonce, &ciphertext, AAD).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn wrong_key_fails_authentication() {
    let ciphertext = encrypt(&test_key(), &test_nonce(), b"secret", AAD).unwrap();
    assert_eq!(
        decrypt(&other_key(), &test_nonce(), &ciphertext, AAD),
        Err(CryptoError::AuthenticationFailed)
    );
}

#[test]
fn wrong_nonce_fails_authentication() {
    let ciphertext = encrypt(&test_key(), &test_nonce(), b"secret", AAD).unwrap();
    assert_eq!(
        decrypt(&test_key(), &other_nonce(), &ciphertext, AAD),
        Err(CryptoError::AuthenticationFailed)
    );
}

#[test]
fn modified_ciphertext_fails_authentication() {
    let mut ciphertext = encrypt(&test_key(), &test_nonce(), b"0123456789abcdef", AAD).unwrap();
    // Flip a byte inside the ciphertext region (not the tag).
    ciphertext[3] ^= 0x01;
    assert_eq!(
        decrypt(&test_key(), &test_nonce(), &ciphertext, AAD),
        Err(CryptoError::AuthenticationFailed)
    );
}

#[test]
fn modified_tag_fails_authentication() {
    let mut ciphertext = encrypt(&test_key(), &test_nonce(), b"0123456789abcdef", AAD).unwrap();
    // Flip the last byte: inside the 16-byte authentication tag.
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;
    assert_eq!(
        decrypt(&test_key(), &test_nonce(), &ciphertext, AAD),
        Err(CryptoError::AuthenticationFailed)
    );
}

#[test]
fn modified_aad_fails_authentication() {
    let ciphertext = encrypt(&test_key(), &test_nonce(), b"secret", AAD).unwrap();
    assert_eq!(
        decrypt(
            &test_key(),
            &test_nonce(),
            &ciphertext,
            b"BondNet/Day3/Tampered"
        ),
        Err(CryptoError::AuthenticationFailed)
    );
}

#[test]
fn truncated_ciphertext_fails_without_panic() {
    let ciphertext = encrypt(&test_key(), &test_nonce(), b"secret", AAD).unwrap();
    // Shorter than the tag itself: must fail cleanly, not panic.
    assert_eq!(
        decrypt(&test_key(), &test_nonce(), &ciphertext[..5], AAD),
        Err(CryptoError::AuthenticationFailed)
    );
    assert_eq!(
        decrypt(&test_key(), &test_nonce(), &[], AAD),
        Err(CryptoError::AuthenticationFailed)
    );
}

#[test]
fn deterministic_test_vector() {
    // Fixed inputs; expected ciphertext generated with libsodium
    // (crypto_aead_xchacha20poly1305_ietf_encrypt), an independent
    // implementation of the same construction — not hand-invented.
    let key_bytes: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce_bytes: [u8; 24] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    ];
    let aad = b"BondNet/Day3/TestVector";
    let plaintext = b"hello bondnet xchacha20poly1305";
    let expected: [u8; 47] = [
        0xf6, 0xa7, 0x63, 0x13, 0xff, 0xf2, 0xef, 0xc1, 0x5d, 0x20, 0x48, 0xab, 0xbf, 0x72, 0xd0,
        0x8b, 0x23, 0x26, 0x4b, 0xcd, 0x9c, 0xe4, 0x2d, 0x9b, 0x10, 0x76, 0x46, 0x87, 0x0e, 0x9d,
        0xc0, 0xd9, 0x3c, 0x4c, 0x21, 0xda, 0xf4, 0xad, 0x99, 0xac, 0x16, 0x6a, 0x58, 0x4c, 0xe2,
        0x6b, 0xe9,
    ];

    let key = CryptoKey::from_slice(&key_bytes).unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes).unwrap();
    let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
    assert_eq!(ciphertext.as_slice(), &expected);
    let recovered = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn different_nonces_give_different_ciphertext() {
    let key = test_key();
    let plaintext = b"same plaintext";
    let c1 = encrypt(&key, &test_nonce(), plaintext, AAD).unwrap();
    let c2 = encrypt(&key, &other_nonce(), plaintext, AAD).unwrap();
    assert_ne!(c1, c2);
}

#[test]
fn same_nonce_reproduces_ciphertext() {
    // Nonce reuse with the same key must NEVER be used in production.
    // This test only demonstrates deterministic AEAD behavior.
    let key = test_key();
    let nonce = test_nonce();
    let plaintext = b"deterministic";
    let c1 = encrypt(&key, &nonce, plaintext, AAD).unwrap();
    let c2 = encrypt(&key, &nonce, plaintext, AAD).unwrap();
    assert_eq!(c1, c2);
}

#[test]
fn invalid_key_length_rejected() {
    for len in [0usize, 16, 31, 33, 64] {
        assert_eq!(
            CryptoKey::from_slice(&vec![0xAA; len]).unwrap_err(),
            CryptoError::InvalidKeyLength,
            "key length {len} must be rejected, not panic"
        );
    }
}

#[test]
fn invalid_nonce_length_rejected() {
    for len in [0usize, 12, 23, 25, 48] {
        assert_eq!(
            Nonce::from_slice(&vec![0xBB; len]).unwrap_err(),
            CryptoError::InvalidNonceLength,
            "nonce length {len} must be rejected, not panic"
        );
    }
}

#[test]
fn key_debug_does_not_leak_bytes() {
    let rendered = format!("{:?}", test_key());
    assert!(
        !rendered.contains("00"),
        "debug output must not contain key bytes"
    );
    assert!(rendered.contains("redacted"));
}
