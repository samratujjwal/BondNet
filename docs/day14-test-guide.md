# BondNet Day 14 — Scheduler Test Guide

Day 14 integrates the Day 4 scheduler with the upload data plane.
Packets are distributed across healthy paths; single-path mode is
unchanged.

---

## How the scheduler chooses

- Each initialized, healthy path is registered with its configured
  `bandwidth_bps` (default 1,000,000 = 1 Mbps).
- The `DefaultScorer` computes `weight = bandwidth × health × latency ×
  loss × jitter × congestion`. With all other stats zero ("unknown"),
  the non-bandwidth factors are 1.0, so weight is proportional to
  bandwidth.
- Smooth weighted round-robin: equal weights → strict alternation;
  3:1 weights → 3:1 distribution, spread smoothly.
- Selection is deterministic for a fixed input sequence (no RNG).
- `Unhealthy` paths are never selected. Zero-weight paths are never
  selected.

## Path weights

Weights are STATIC in Day 14 — configured via `bandwidth_bps`, not
measured. There is no active probing. To change a weight, update the
path's config and re-sync (the plane re-syncs before every send, so a
health change takes effect on the next packet; a bandwidth change needs
a config update).

## Failed paths

- A send error increments `send_errors` and returns
  `MultipathError::SendFailed { path_id, .. }`. The path REMAINS
  eligible. This is deliberate: Day 14 does not implement automatic
  failover or health detection.
- To exclude a path, call `set_path_health(id, PathHealth::Unhealthy)`
  (operator action). The next `send_wintun_packet` will not select it.
- If no path is eligible, the packet is dropped and `no_eligible_path`
  is counted. The error is `MultipathError::NoEligiblePath`.

## Sequence numbers

Per-path independent counters. Path 1's 5th packet has seq=5; path 2's
3rd packet has seq=3. There is NO global order. A server-side reorder
buffer (Day 5) exists but is NOT integrated — out-of-order arrival
across paths is expected and documented.

## Simulation vs real two-network testing

The unit tests verify SCHEDULING DECISIONS (which path ID is chosen for
each packet in sequence), not actual network delivery. They use real
`UdpPath` sockets bound to loopback; sends may fail in restricted
sandboxes, but the selection logic is fully exercised.

Real proof of two-network distribution requires:
1. Two physical interfaces with distinct IPs (see Day 13 guide).
2. `path-diag` or a future multipath sender running with both paths.
3. Server log showing `DATA_RX` with both path IDs from two source
   addresses, in the expected ratio.

## Out-of-order delivery

Packets scheduled across paths can arrive out of order at the VPS.
The server processes each independently (per-path sequences). The
application must tolerate reordering until Day 15 integrates the
reorder buffer.

## Single-path mode

Unchanged. `DataPlane` (single `UdpPath`) still exists and all Day 9/11
tests pass. `MultipathDataPlane` with one path selects it for every
packet (tested).

---

## Automated tests

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

New Day 14 coverage (`multipath::tests`):

1. One healthy path: all packets use it.
2. Two equal paths: 5/5 split over 10 packets (smooth round-robin).
3. 3:1 weights: 30/10 split over 40 packets.
4. Unhealthy path gets no packets; recovery restores eligibility.
5. No eligible path: `NoEligiblePath` error + counter.
6. Shut-down path not selected; re-init restores without duplicates.
7. Per-path sequences independent (1,2,3 on path 1; 1,2 on path 2).
8. Empty/oversized rejected before scheduling, counted.

## CLI

Day 14 adds no new CLI flags. The `path-diag` command (Day 13) remains
the two-path diagnostic. A multipath sender CLI is Day 15+.

## What remains unimplemented

Packet reordering/delivery reconstruction, global sequencing,
ACKs/retransmission, replay protection, encryption, active probing,
production failure detection, MTU discovery, route/DNS changes.
