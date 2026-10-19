//! Day 19: secure session with domain-separated keys and nonce counters.
//!
//! # Security issues fixed from Day 18
//!
//! 1. **Nonce reuse for control packets**: Day 18 used `sequence=0` for all
//!    PathKeepalive packets. Encrypting multiple keepalives with the same
//!    (key, nonce) violates AEAD security.
//! 2. **No domain separation**: DATA and control used the same key.
//! 3. **Restart safety**: Counters reset on restart; if (PSK, session_id)
//!    was reused, nonces would repeat.
//!
//! # Day 19 design
//!
//! ## Domain-separated keys (4 domains)
//!
//! ```text
//! PSK + session_salt
//!   ├─ HKDF(info="BondNet-v1-upload-data")   → Client→Server DATA
//!   ├─ HKDF(info="BondNet-v1-return-data")   → Server→Client DATA
//!   ├─ HKDF(info="BondNet-v1-upload-ctrl")   → Client→Server control
//!   └─ HKDF(info="BondNet-v1-return-ctrl")   → Server→Client control
//! ```
//!
//! ## Nonce format (24 bytes)
//!
//! ```text
//! domain (1) || counter (8, BE) || session_id (8, BE) || zeros (7)
//! ```
//!
//! - `domain`: 0x00=upload-data, 0x01=return-data, 0x02=upload-ctrl, 0x03=return-ctrl
//! - `counter`: per-domain AtomicU64, starts at 1, never resets within a session
//! - `session_id`: binds nonce to session (defense in depth)
//!
//! ## Session salt (restart safety)
//!
//! - Client generates 32-byte random `session_salt` per `SecureSession`
//! - Sent in PathHello payload; server caches per session_id
//! - Keys derived with `salt = session_id || session_salt`
//! - Client restart → new salt → new keys → no nonce reuse
//!
//! ## AAD
//!
//! The 36-byte header is AAD, authenticating packet_type, session_id,
//! path_id, sequence, payload_len.

use std::sync::atomic::{AtomicU64, Ordering};

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CryptoError;
use crate::key::{CryptoKey, Nonce};

/// Purpose/domain of a key. Each domain has an independent key and
/// nonce counter, preventing cross-purpose nonce reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDomain {
    /// Client → Server DATA packets.
    UploadData,
    /// Server → Client DATA packets.
    ReturnData,
    /// Client → Server control packets (PathKeepalive requests).
    UploadControl,
    /// Server → Client control packets (PathKeepalive responses).
    ReturnControl,
}

impl KeyDomain {
    fn as_byte(self) -> u8 {
        match self {
            KeyDomain::UploadData => 0x00,
            KeyDomain::ReturnData => 0x01,
            KeyDomain::UploadControl => 0x02,
            KeyDomain::ReturnControl => 0x03,
        }
    }

    fn info_string(self) -> &'static str {
        match self {
            KeyDomain::UploadData => "BondNet-v1-upload-data",
            KeyDomain::ReturnData => "BondNet-v1-return-data",
            KeyDomain::UploadControl => "BondNet-v1-upload-ctrl",
            KeyDomain::ReturnControl => "BondNet-v1-return-ctrl",
        }
    }
}

/// A secure session with domain-separated keys.
///
/// Each of the 4 domains has:
/// - An independent 32-byte key (derived via HKDF)
/// - An independent AtomicU64 nonce counter (starts at 1)
///
/// The `session_salt` is a 32-byte random value generated per session.
/// It ensures that a client restart produces fresh keys, even if the
/// session_id is reused.
pub struct SecureSession {
    session_id: u64,
    session_salt: [u8; 32],
    upload_data_key: CryptoKey,
    return_data_key: CryptoKey,
    upload_ctrl_key: CryptoKey,
    return_ctrl_key: CryptoKey,
    upload_data_ctr: AtomicU64,
    return_data_ctr: AtomicU64,
    upload_ctrl_ctr: AtomicU64,
    return_ctrl_ctr: AtomicU64,
}

impl SecureSession {
    /// Create a session from PSK, session ID, and salt.
    ///
    /// The salt MUST be unique per session lifetime. The client generates
    /// a fresh random salt per startup; the server uses the salt from
    /// PathHello.
    pub fn new(
        psk: &CryptoKey,
        session_id: u64,
        session_salt: [u8; 32],
    ) -> Result<Self, CryptoError> {
        // Salt for HKDF: session_id || session_salt
        let mut hkdf_salt = [0u8; 40];
        hkdf_salt[0..8].copy_from_slice(&session_id.to_be_bytes());
        hkdf_salt[8..40].copy_from_slice(&session_salt);

        let upload_data_key =
            Self::derive_key(psk, &hkdf_salt, KeyDomain::UploadData.info_string())?;
        let return_data_key =
            Self::derive_key(psk, &hkdf_salt, KeyDomain::ReturnData.info_string())?;
        let upload_ctrl_key =
            Self::derive_key(psk, &hkdf_salt, KeyDomain::UploadControl.info_string())?;
        let return_ctrl_key =
            Self::derive_key(psk, &hkdf_salt, KeyDomain::ReturnControl.info_string())?;

        Ok(Self {
            session_id,
            session_salt,
            upload_data_key,
            return_data_key,
            upload_ctrl_key,
            return_ctrl_key,
            upload_data_ctr: AtomicU64::new(1),
            return_data_ctr: AtomicU64::new(1),
            upload_ctrl_ctr: AtomicU64::new(1),
            return_ctrl_ctr: AtomicU64::new(1),
        })
    }

    /// Create a session with a fresh random salt (client side).
    ///
    /// Uses a cryptographically secure RNG. The salt must be sent to the
    /// peer (via PathHello) for them to derive matching keys.
    pub fn new_with_random_salt(psk: &CryptoKey, session_id: u64) -> Result<Self, CryptoError> {
        let mut salt = [0u8; 32];
        getrandom::fill(&mut salt).map_err(|_| CryptoError::KeyDerivationFailed)?;
        Self::new(psk, session_id, salt)
    }

    fn derive_key(psk: &CryptoKey, salt: &[u8], info: &str) -> Result<CryptoKey, CryptoError> {
        let hk = Hkdf::<Sha256>::new(Some(salt), psk.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(info.as_bytes(), &mut okm)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        CryptoKey::from_slice(&okm)
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn session_salt(&self) -> &[u8; 32] {
        &self.session_salt
    }

    fn key_for(&self, domain: KeyDomain) -> &CryptoKey {
        match domain {
            KeyDomain::UploadData => &self.upload_data_key,
            KeyDomain::ReturnData => &self.return_data_key,
            KeyDomain::UploadControl => &self.upload_ctrl_key,
            KeyDomain::ReturnControl => &self.return_ctrl_key,
        }
    }

    fn counter_for(&self, domain: KeyDomain) -> &AtomicU64 {
        match domain {
            KeyDomain::UploadData => &self.upload_data_ctr,
            KeyDomain::ReturnData => &self.return_data_ctr,
            KeyDomain::UploadControl => &self.upload_ctrl_ctr,
            KeyDomain::ReturnControl => &self.return_ctrl_ctr,
        }
    }

    /// Allocate the next nonce for a domain.
    ///
    /// The counter is incremented atomically, ensuring concurrent tasks
    /// never allocate the same nonce. The counter never resets within
    /// a session's lifetime.
    pub fn next_nonce(&self, domain: KeyDomain) -> Nonce {
        let counter = self.counter_for(domain).fetch_add(1, Ordering::SeqCst);
        let mut bytes = [0u8; 24];
        bytes[0] = domain.as_byte();
        bytes[1..9].copy_from_slice(&counter.to_be_bytes());
        bytes[9..17].copy_from_slice(&self.session_id.to_be_bytes());
        // bytes[17..24] remain zero.
        Nonce::from_slice(&bytes).expect("24 bytes is valid")
    }

    /// Construct a nonce for a specific counter value (for decryption).
    ///
    /// The decryptor must know the counter value. For DATA packets, the
    /// counter is derived from the sequence number (see below). For
    /// control packets, the counter is in the payload.
    pub fn nonce_for_counter(&self, domain: KeyDomain, counter: u64) -> Nonce {
        let mut bytes = [0u8; 24];
        bytes[0] = domain.as_byte();
        bytes[1..9].copy_from_slice(&counter.to_be_bytes());
        bytes[9..17].copy_from_slice(&self.session_id.to_be_bytes());
        Nonce::from_slice(&bytes).expect("24 bytes is valid")
    }

    /// Encrypt with a domain-specific key and fresh nonce.
    ///
    /// Returns `(nonce_counter, ciphertext || tag)`. The caller must
    /// convey the `nonce_counter` to the decryptor (for DATA, it's the
    /// sequence number; for control, it's in the payload).
    pub fn encrypt(
        &self,
        domain: KeyDomain,
        header_aad: &[u8; 36],
        plaintext: &[u8],
    ) -> Result<(u64, Vec<u8>), CryptoError> {
        let counter = self.counter_for(domain).fetch_add(1, Ordering::SeqCst);
        let nonce = self.nonce_for_counter(domain, counter);
        let key = self.key_for(domain);
        let ct = crate::aead::encrypt(key, &nonce, plaintext, header_aad)?;
        Ok((counter, ct))
    }

    /// Encrypt with an explicit counter value (for DATA packets where the
    /// sequence number serves as the nonce counter).
    ///
    /// The caller must ensure the counter is unique per (domain, session).
    /// For DATA, the session-wide sequence number provides this guarantee.
    pub fn encrypt_with_counter(
        &self,
        domain: KeyDomain,
        counter: u64,
        header_aad: &[u8; 36],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.nonce_for_counter(domain, counter);
        let key = self.key_for(domain);
        crate::aead::encrypt(key, &nonce, plaintext, header_aad)
    }

    /// Decrypt with a domain-specific key and explicit counter.
    pub fn decrypt(
        &self,
        domain: KeyDomain,
        counter: u64,
        header_aad: &[u8; 36],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.nonce_for_counter(domain, counter);
        let key = self.key_for(domain);
        crate::aead::decrypt(key, &nonce, ciphertext, header_aad)
    }
}

// SecureSession can be cloned, but the clone resets nonce counters.
// This is ONLY safe for the server's session cache (where the session
// is cloned out of the map for use, and the map retains the original
// with its counters). Production code must not clone a session and
// use both copies for encryption, as that would reuse nonces.
impl Clone for SecureSession {
    fn clone(&self) -> Self {
        Self {
            session_id: self.session_id,
            session_salt: self.session_salt,
            upload_data_key: self.upload_data_key.clone(),
            return_data_key: self.return_data_key.clone(),
            upload_ctrl_key: self.upload_ctrl_key.clone(),
            return_ctrl_key: self.return_ctrl_key.clone(),
            // Note: counters are reset. The server clones from the cache
            // for decryption only (which doesn't increment counters).
            // For encryption, use the original, not a clone.
            upload_data_ctr: AtomicU64::new(self.upload_data_ctr.load(Ordering::SeqCst)),
            return_data_ctr: AtomicU64::new(self.return_data_ctr.load(Ordering::SeqCst)),
            upload_ctrl_ctr: AtomicU64::new(self.upload_ctrl_ctr.load(Ordering::SeqCst)),
            return_ctrl_ctr: AtomicU64::new(self.return_ctrl_ctr.load(Ordering::SeqCst)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_psk() -> CryptoKey {
        CryptoKey::from_slice(&[0x42; 32]).unwrap()
    }

    fn test_salt() -> [u8; 32] {
        [0x11; 32]
    }

    #[test]
    fn domain_keys_are_isolated() {
        let s = SecureSession::new(&test_psk(), 1001, test_salt()).unwrap();
        let header = [0u8; 36];
        // Encrypt with UploadData...
        let (ctr, ct) = s.encrypt(KeyDomain::UploadData, &header, b"hello").unwrap();
        // ...decrypt with ReturnData must fail (different key).
        assert!(s.decrypt(KeyDomain::ReturnData, ctr, &header, &ct).is_err());
        // ...decrypt with UploadData succeeds.
        let pt = s.decrypt(KeyDomain::UploadData, ctr, &header, &ct).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn nonces_are_unique_per_domain() {
        let s = SecureSession::new(&test_psk(), 1001, test_salt()).unwrap();
        let n1 = s.next_nonce(KeyDomain::UploadData);
        let n2 = s.next_nonce(KeyDomain::UploadData);
        let n3 = s.next_nonce(KeyDomain::UploadControl);
        // Same domain, different counters → different nonces.
        assert_ne!(n1.as_bytes(), n2.as_bytes());
        // Different domains → different nonces (domain byte differs).
        assert_ne!(n1.as_bytes()[0], n3.as_bytes()[0]);
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let s1 = SecureSession::new(&test_psk(), 1001, [0x11; 32]).unwrap();
        let s2 = SecureSession::new(&test_psk(), 1001, [0x22; 32]).unwrap();
        let header = [0u8; 36];
        let (ctr, ct) = s1.encrypt(KeyDomain::UploadData, &header, b"hi").unwrap();
        // s2 has different keys (different salt) → decrypt fails.
        assert!(
            s2.decrypt(KeyDomain::UploadData, ctr, &header, &ct)
                .is_err()
        );
    }

    #[test]
    fn concurrent_nonce_allocation_is_unique() {
        use std::collections::HashSet;
        use std::sync::Arc;
        let s = Arc::new(SecureSession::new(&test_psk(), 1001, test_salt()).unwrap());
        let mut handles = vec![];
        for _ in 0..10 {
            let sc = Arc::clone(&s);
            handles.push(std::thread::spawn(move || {
                let mut nonces = vec![];
                for _ in 0..100 {
                    nonces.push(sc.next_nonce(KeyDomain::UploadData));
                }
                nonces
            }));
        }
        let mut all = HashSet::new();
        for h in handles {
            for n in h.join().unwrap() {
                // All 1000 nonces must be unique.
                assert!(all.insert(*n.as_bytes()));
            }
        }
        assert_eq!(all.len(), 1000);
    }
}
