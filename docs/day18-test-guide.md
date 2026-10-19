# BondNet Day 18 Test Guide — Secure Transport Integration

## What Day 18 Implements

Authenticated encryption for the DATA transport using XChaCha20-Poly1305:

1. **Key derivation**: HKDF-SHA256 from PSK → directional session keys
2. **Nonce construction**: deterministic, unique per (key, message)
3. **AAD**: 36-byte header authenticates packet_type, session_id, path_id, sequence
4. **Server**: authenticates BEFORE `record_packet` (prevents endpoint hijacking)
5. **Client**: encrypts upload DATA via `UdpPath`

## Threat Model

**Attacker can**: observe, modify, replay, inject UDP packets.
**Attacker cannot**: know the 32-byte PSK.

**Guarantees** (when PSK is configured on both ends):
- Confidentiality: IP payloads are encrypted
- Integrity: modified packets are rejected (no plaintext leaks)
- Authentication: only PSK holders can create valid packets
- Anti-replay: sequence numbers are authenticated; duplicates dropped by reorder buffer

**NOT guaranteed**:
- Protection against PSK compromise (use a strong random PSK)
- Forward secrecy (same PSK = same keys; rotate manually)
- DoS resistance (attacker can still flood UDP)

## Key Hierarchy

```
PSK (32 bytes, hex via --psk)
  ├─ HKDF(salt=session_id, info="BondNet-v1-upload") → Upload key (client→server)
  └─ HKDF(salt=session_id, info="BondNet-v1-return") → Return key (server→client)
```

**CRITICAL**: `session_id` MUST be unique per session. Reusing a session_id
with the same PSK causes key reuse → nonce reuse → catastrophic security failure.

## Nonce Construction (24 bytes)

```
session_id (8, BE) || sequence (8, BE) || direction (1) || zeros (7)
```

- `sequence`: session-wide logical sequence (unique per direction)
- `direction`: 0x00=upload, 0x01=return
- Keys are directional, so nonce is unique per (key, message)

## Wire Format

```
[36-byte header (plaintext)] [ciphertext || 16-byte Poly1305 tag]
```

- Header is plaintext (needed for routing) but **authenticated via AAD**
- `payload_len` in header = ciphertext length
- 36-byte header layout UNCHANGED

## Configuration

### Client
```powershell
# Generate a random PSK (do this once, keep it secret)
# Example: 64 hex chars = 32 bytes
bondnet-client --psk 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff ...
```

### Server
```powershell
bondnet-server --psk <same-64-hex-chars> ...
```

**Without `--psk`**: plaintext mode (backward compatible, with warning).
**With `--psk` on client but not server**: server drops packets (auth failure).
This is fail-closed, not silent fallback.

## Tests

### Crypto unit tests (21 tests)
```powershell
cargo test -p bondnet-crypto
```
- 17 AEAD tests (round-trip, tamper, wrong key/nonce)
- 4 session tests (key derivation, nonce uniqueness, directional isolation)

### Integration tests
```powershell
# Client (92 tests, includes Day 17)
cargo test -p bondnet-client --lib

# Server (56 tests)
cargo test -p bondnet-server --lib
```

### Manual test: encrypted upload
1. Start server with `--psk <hex>` and TUN
2. Start client with `--psk <same-hex>`
3. Send traffic; verify `auth_failures` stays 0
4. Try with wrong PSK; verify `auth_failures` increments, no TUN writes

## Metrics

- Server: `auth_failures` — packets dropped due to failed authentication
- These packets NEVER reach `record_packet`, so they cannot hijack endpoints

## Limitations (Days 19-20)

1. **Return path encryption**: Upload (client→server) is implemented. Return
   (server→client) uses the same `SecureSession` but the integration in
   `build_return_datagram` is not yet wired. Documented for Day 19.
2. **No handshake**: PSK is manually configured. No forward secrecy.
3. **No key rotation**: Restart with new PSK to rotate.
4. **PathKeepalive**: Currently plaintext. Does not affect security-critical
   state (only scheduling health), but a future milestone should authenticate it.
5. **Session ID uniqueness**: Operator must ensure unique session_id per run.
   Consider adding `--generate-session-id` in Day 19.

## Files Changed

**New**:
- `crates/bondnet-crypto/src/session.rs` — SecureSession, key derivation, nonces
- `docs/day18-test-guide.md` — this file

**Modified**:
- `crates/bondnet-crypto/Cargo.toml` — added hkdf, sha2
- `crates/bondnet-crypto/src/lib.rs` — export session module
- `crates/bondnet-crypto/src/error.rs` — KeyDerivationFailed
- `crates/bondnet-crypto/src/session.rs` — Clone derive
- `crates/bondnet-client/Cargo.toml` — bondnet-crypto dependency
- `crates/bondnet-client/src/transport.rs` — UdpPath encryption, header_aad
- `crates/bondnet-client/src/multipath.rs` — secure_session field
- `crates/bondnet-server/Cargo.toml` — bondnet-crypto dependency
- `crates/bondnet-server/src/config.rs` — psk field, --psk parsing
- `crates/bondnet-server/src/server.rs` — authenticate_data, auth_failures metric,
  SecureSession cache, psk field
