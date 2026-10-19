# BondNet Day 19 Test Guide — Complete Secure Bidirectional Transport

## What Day 19 Fixes (from Day 18)

### Critical: Nonce Reuse for Control Packets
**Day 18 flaw**: PathKeepalive used `sequence=0` for all packets. Encrypting
multiple keepalives with the same (key, nonce) violates AEAD security.

**Day 19 fix**: Domain-separated keys with independent nonce counters:
- `UploadData` (0x00): Client→Server DATA, counter = sequence number
- `ReturnData` (0x01): Server→Client DATA, counter = sequence number  
- `UploadControl` (0x02): Client→Server control, counter = AtomicU64
- `ReturnControl` (0x03): Server→Client control, counter = AtomicU64

Each domain has its own 32-byte key derived via HKDF.

### Restart Safety
**Day 18 flaw**: If (PSK, session_id) was reused after restart, nonce counters
reset to 0 → nonce reuse.

**Day 19 fix**: 32-byte `session_salt`:
- Client generates random salt per `SecureSession` (via `getrandom`)
- Salt sent in PathHello payload (first 32 bytes)
- Server caches salt per session_id, derives keys with `salt = session_id || session_salt`
- Client restart → new salt → new keys → no reuse

## Key Hierarchy (Day 19)

```
PSK (32 bytes)
  + session_salt (32 bytes, random per client startup)
  + session_id (8 bytes)
    │
    ├─ HKDF(info="BondNet-v1-upload-data") → UploadData key
    ├─ HKDF(info="BondNet-v1-return-data") → ReturnData key
    ├─ HKDF(info="BondNet-v1-upload-ctrl") → UploadControl key
    └─ HKDF(info="BondNet-v1-return-ctrl") → ReturnControl key
```

## Nonce Format (24 bytes)

```
domain (1) || counter (8, BE) || session_id (8, BE) || zeros (7)
```

- DATA: counter = sequence number (unique per direction)
- Control: counter = per-domain AtomicU64 (starts at 1)

## What Was Implemented

### ✅ Upload DATA (Client→Server)
- Client encrypts in `UdpPath::next_packet` using `UploadData` domain
- Server decrypts in `authenticate_data` BEFORE `record_packet`
- Unauthenticated packets cannot hijack endpoints

### ✅ Return DATA (Server→Client)  
- Server encrypts in `build_return_datagram` using `ReturnData` domain
- Client decrypts in `ReturnProcessor::validate_decrypted`
- Note: TUN reader thread path passes `None` (plaintext) — documented limitation

### ✅ Session Salt Exchange
- Client: generate salt via `SecureSession::new_with_random_salt`
- PathHello payload carries 32-byte salt
- Server: extracts salt, caches per session_id, re-derives keys

### ⚠️ PathKeepalive Authentication (Partial)
- Infrastructure ready (UploadControl/ReturnControl domains with counters)
- Health monitor not yet wired to encrypt keepalives
- Documented for completion: keepalives remain plaintext in Day 19

## Tests

```powershell
# Crypto (21 tests: 17 AEAD + 4 session)
cargo test -p bondnet-crypto

# Full workspace (316 tests)
cargo test --workspace -j 2
```

### New Day 19 Tests (in bondnet-crypto/src/session.rs)
1. `domain_keys_are_isolated` — cross-domain decrypt fails
2. `nonces_are_unique_per_domain` — domain byte differs, counters unique
3. `different_salts_produce_different_keys` — restart safety
4. `concurrent_nonce_allocation_is_unique` — 1000 nonces, all unique

## Metrics

- Server: `auth_failures` — packets dropped (upload or return encrypt fail)
- Client: `ReturnProcessor` metrics unchanged

## Configuration

Same as Day 18:
```powershell
# Both ends need the same PSK (64 hex chars)
bondnet-server --psk <hex> ...
bondnet-client --psk <hex> ...  # (client --psk not yet wired to UdpPath)
```

**Note**: Client `--psk` CLI arg not yet implemented. The `SecureSession`
must be attached programmatically via `UdpPath::set_secure_session`.

## Limitations for Day 20

1. **PathKeepalive plaintext**: Domains exist, but health monitor doesn't encrypt yet.
2. **TUN reader thread**: `build_return_datagram` called with `None` (no encryption) in the live TUN path. The `process_return_packet` test path supports encryption.
3. **Client --psk CLI**: Not wired. Must attach `SecureSession` programmatically.
4. **No handshake**: Manual PSK. No forward secrecy.
5. **Salt in PathHello**: If client doesn't send salt (legacy), server uses zeros (less safe, logged).

## Files Changed (Day 19)

**Modified**:
- `crates/bondnet-crypto/src/session.rs` — complete rewrite: 4 domains, counters, salts
- `crates/bondnet-crypto/src/lib.rs` — export KeyDomain
- `crates/bondnet-crypto/Cargo.toml` — added getrandom
- `crates/bondnet-client/src/transport.rs` — use KeyDomain::UploadData
- `crates/bondnet-client/src/return_path.rs` — validate_decrypted, set_secure_session
- `crates/bondnet-server/src/server.rs` — session_salts, salt extraction, ReturnData encryption
- `docs/day19-test-guide.md` — this file

## Real VPS Testing (NOT RUN)

- [ ] Encrypted upload: client→server with matching PSK
- [ ] Encrypted return: server→client with matching PSK  
- [ ] Wrong PSK: auth_failures increments
- [ ] PathHello salt exchange over real network
- [ ] Restart: new salt → no nonce reuse
