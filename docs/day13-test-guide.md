# BondNet Day 13 — Two-Path Test Guide

Day 13 prepares two independent physical paths. It does NOT send
traffic over both, schedule, bond, or fail over. Single-path mode is
unchanged.

---

## What makes a path independent

- Its own UDP socket (own file descriptor).
- Its own local bind address (selects the physical interface via the OS
  routing table).
- Its own remote endpoint (normally the same VPS, but a different
  address/port is allowed).
- Its own configured `path_id` (unique within the manager).
- Its own transport metrics and error state.
- Its own lifecycle: init failure or shutdown of one never affects the
  other.

What does NOT make paths independent: two sockets bound to the same
local IP, or two path IDs sharing one socket. The manager prevents the
second (duplicate IDs rejected); the first is a configuration error the
operator must avoid.

## Proving two distinct physical network paths

A second socket bound to another local IP on the same machine is NOT
proof of two independent Internet connections. Real proof requires:

1. Two different local IPs, each owned by a different physical
   interface (e.g. Wi-Fi `192.168.1.10` and Ethernet `192.168.2.10`,
   or Wi-Fi and a USB tether).
2. `path-diag` shows both paths initialized with distinct local
   addresses.
3. The server's verbose log shows `RX` lines for both path IDs from
   two different source addresses (the client's two public IPs, or
   two different NAT mappings).
4. Disconnecting one physical interface leaves the other path's
   `PathHello` flow uninterrupted (observed in the server log).

Without (3) and (4), you have two sockets, not two paths.

---

## Automated tests (Level A)

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace
```

```powershell
cargo check --workspace --target x86_64-pc-windows-msvc --tests
```

New Day 13 coverage:

- `config::tests`: duplicate path IDs rejected (even with different
  locals), zero remote port on enabled path rejected, disabled path
  with zero port allowed, empty name rejected, non-IPv4 rejected,
  session attached correctly via `to_udp_path_config`.
- `path_manager::tests`: two paths bind to distinct sockets; disabled
  path not bound; A-fails/B-works and B-fails/A-works; shutdown of one
  leaves the other; shutdown_all idempotent; per-path sequence counters
  independent.
- `path_diag::tests`: CLI parsing, duplicate IDs rejected, disabled
  flag, missing session ID rejected.
- `server::tests`: two path IDs tracked independently (counters,
  sequences, remote addresses); return goes to the correct path's
  endpoint; unknown path ID creates no endpoint.

## Local two-path validation

On any machine (no VPS needed — sockets bind locally, sends fail
harmlessly in restricted sandboxes):

```bash
cargo run -p bondnet-client --bin bondnet-client -- path-diag \
  --session-id 1001 \
  --path1-id 1 --path1-local 127.0.0.1:0 --path1-remote 127.0.0.1:51820 \
  --path2-id 2 --path2-local 127.0.0.1:0 --path2-remote 127.0.0.1:51820 \
  --verbose
```

Expected: two `path ... initialized=true` lines with distinct local
ports, two `PathHello sent` lines, clean shutdown.

Failure injection (proves isolation):

```bash
# Duplicate IDs — must fail fast with a clear error, no sockets bound:
cargo run -p bondnet-client --bin bondnet-client -- path-diag \
  --session-id 1001 \
  --path1-id 1 --path1-local 127.0.0.1:0 --path1-remote 127.0.0.1:51820 \
  --path2-id 1 --path2-local 127.0.0.1:0 --path2-remote 127.0.0.1:51820
```

## Real two-path validation (needs your hardware)

Windows (PowerShell) — replace the locals with your two interface IPs,
the remote with your VPS:

```powershell
cargo run -p bondnet-client --bin bondnet-client -- path-diag `
  --session-id 1001 `
  --path1-id 1 --path1-name wifi --path1-local 192.168.1.10:0 --path1-remote <VPS_IP>:51820 `
  --path2-id 2 --path2-name ethernet --path2-local 192.168.2.10:0 --path2-remote <VPS_IP>:51820 `
  --verbose
```

On the VPS, the server log must show `RX` lines with `path=1` and
`path=2` from two different source addresses.

Find your interface IPs first:

```powershell
Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike "127.*"} |
  Select-Object IPAddress, InterfaceAlias
```

## Single-path mode (unchanged)

All existing commands work exactly as before:

```powershell
cargo run -p bondnet-client --bin bondnet-client -- tunnel-smoke `
  --local 192.168.1.10:0 --remote <VPS_IP>:51820 `
  --path-id 1 --session-id 1001 --synthetic --verbose
```

No new flags, no changed defaults, no config migration.

---

## What remains unimplemented

Multipath scheduling, packet distribution across paths, reorder buffer
for multiple paths, bonding/aggregation, automatic failover,
encryption, ACKs/retransmission, replay protection, route/DNS changes,
MTU discovery, production authentication. Those are Day 14+.

## Safety

- Never route tunnel UDP through Wintun; `path-diag` never touches
  routes or DNS.
- The protocol is still plaintext and unauthenticated — test against
  your own VPS only.
