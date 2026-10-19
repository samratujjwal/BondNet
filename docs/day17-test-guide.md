# BondNet Day 17 Test Guide — Failure Detection, Automatic Failover & Recovery

## What Day 17 Implements

A bounded, testable failure-detection and recovery mechanism:

1. **Path health state machine** (`bondnet-client/src/health.rs`):
   `Unknown → Healthy ⇄ Degraded → Unhealthy → Recovering → Healthy`
2. **Liveness detection**: `PathKeepalive` heartbeat probes with server echo
3. **Automatic failover**: unhealthy paths excluded from scheduler
4. **Recovery**: consecutive successes required; flapping protection
5. **Diagnostics**: `health-diag` command + per-path metrics

## Default Thresholds

| Parameter | Default | Why |
|-----------|---------|-----|
| Heartbeat interval | 1s | Frequent enough for fast detection, low overhead |
| Probe timeout | 500ms | 2x typical LAN RTT; conservative for first impl |
| Degraded threshold | 2 misses | Early warning, still eligible |
| Unhealthy threshold | 3 misses | 3s of silence = declared failed |
| Recovery threshold | 3 successes | Prevents flapping on intermittent links |
| Send error threshold | 5 errors | Local errors → Degraded (not Unhealthy) |

## Key Design Decisions

### What the metrics prove (and don't prove)

- **Proves**: The client sent a probe; the server echoed it; the path is bidirectionally reachable at the UDP level.
- **Does NOT prove**: The physical interface is up; the Internet is reachable; DATA packets are being delivered.

### Local send error vs remote failure

- A local UDP `send()` error means the OS refused the packet (e.g., network unreachable, no route). It is evidence of LOCAL trouble.
- A missed heartbeat means no response arrived within the timeout. It is evidence the path is not responding, NOT proof the physical link is down.
- Send errors contribute to `Degraded` but never alone cause `Unhealthy`. Only missed heartbeats cause `Unhealthy`.

### Sequence numbers during failover

The session-wide sequence counter (`MultipathDataPlane::upload_sequence`) is NEVER reset during failover. Packets keep their allocated sequences; the reorder buffer on the receiving side handles out-of-order arrival across paths.

## Automated Tests (Level A)

```powershell
# All workspace tests (includes 17 new Day 17 tests)
cargo test --workspace

# Client tests only (health state machine + failover)
cargo test -p bondnet-client --lib

# Specific Day 17 tests
cargo test -p bondnet-client --lib health::
cargo test -p bondnet-client --lib unhealthy_path_excluded
cargo test -p bondnet-client --lib all_unhealthy_returns_no_eligible
```

### New tests (17 total)

**`health.rs` (10 tests)**:
1. `healthy_path_remains_eligible` — healthy path stays healthy
2. `misses_drive_degraded_then_unhealthy` — 2 misses → Degraded, 3 → Unhealthy
3. `stale_response_does_not_affect_health` — unknown/duplicate probe IDs ignored
4. `recovery_requires_consecutive_successes` — Unhealthy → Recovering → Healthy (3 successes)
5. `miss_during_recovery_aborts_to_unhealthy` — flapping protection
6. `send_errors_cause_degraded_not_unhealthy` — 5 errors → Degraded, never Unhealthy
7. `invalid_config_rejected` — bad thresholds rejected
8. `response_updates_correct_path` — per-path isolation
9. `tracker_does_not_allocate_sequences` — probe IDs ≠ data sequences
10. `only_pathkeepalive_affects_tracker` — control/data separation

**`multipath.rs` (4 tests)**:
11. `unhealthy_path_excluded_from_scheduling` — scheduler skips unhealthy
12. `traffic_continues_on_healthy_path` — failover works
13. `all_unhealthy_returns_no_eligible_path` — explicit error, not silent drop
14. `sequences_stable_across_failover` — no reset, no duplicates

**`health_monitor.rs` (3 tests)**:
15. `shutdown_cancels_tasks_cleanly` — no hang on shutdown
16. `repeated_start_shutdown_no_leak` — 3 cycles, no leak
17. `double_start_is_error` — prevents task leak

## Diagnostics (Level A)

```powershell
# Deterministic simulation (no network needed)
cargo run -p bondnet-client --bin bondnet-client -- health-diag

# Verbose (shows scheduler mapping)
cargo run -p bondnet-client --bin bondnet-client -- health-diag --verbose
```

Expected output:
```
=== BondNet Day 17 Health Diagnostics ===

State machine:
  Unknown → Healthy ⇄ Degraded → Unhealthy → Recovering → Healthy

Default thresholds:
  Heartbeat interval: 1s
  Probe timeout: 500ms
  Degraded after 2 misses
  Unhealthy after 3 misses
  Recovery after 3 successes
  Degraded after 5 send errors

--- Simulated scenario: failure then recovery ---
After 1 response: Healthy
After 2 misses: Degraded
After 3 misses: Unhealthy
After 1 recovery response(s): Recovering
After 2 recovery response(s): Recovering
After 3 recovery response(s): Healthy

Metrics:
  Probes sent: 4
  Responses received: 4
  Misses: 3
  State transitions: 5
  Recoveries: 1
```

## Manual Testing (Level B — Real Windows)

### Prerequisites
- Server running on VPS with Day 17 code (supports PathKeepalive echo)
- Client on Windows with two paths configured

### Test: Failover on path failure
1. Start client with both paths healthy.
2. Disconnect one physical interface (e.g., unplug Ethernet, keep WiFi).
3. Observe: after ~3s, the disconnected path is marked Unhealthy.
4. Verify: traffic continues on the remaining path (check `MultipathMetrics`).
5. Reconnect the interface.
6. Observe: after ~3 heartbeats, the path returns to Healthy.

### Test: All paths down
1. Disconnect both interfaces.
2. Verify: `send_wintun_packet` returns `NoEligiblePath` (explicit error, not silent).

## What Requires VPS Testing (Level B/C)

- [ ] Server PathKeepalive echo (real network)
- [ ] Health monitor with real probes (not simulated)
- [ ] Failover with physical interface disconnect
- [ ] Recovery with physical interface reconnect
- [ ] No flapping on intermittent link

## Limitations

1. **No retransmission**: Day 17 detects failure and reroutes NEW packets. Packets already sent on a failed path are lost (gap timeout skips them).
2. **Not lossless**: Failover is not guaranteed lossless. The reorder buffer handles out-of-order, but missing packets are skipped after 200ms.
3. **Heartbeat overhead**: 1 probe/sec/path. Negligible for 2 paths, but scales linearly.
4. **No RTT measurement**: The probe/response is used for liveness only, not for RTT-based scheduling (future work).
5. **Operator override**: `set_path_health` (operator API) still works and can conflict with automatic health. The monitor overwrites on its next update.

## Files Changed

**New**:
- `crates/bondnet-client/src/health.rs` — state machine, config, metrics
- `crates/bondnet-client/src/health_monitor.rs` — background task, probe sender/receiver
- `crates/bondnet-client/src/health_diag.rs` — `health-diag` CLI command
- `docs/day17-test-guide.md` — this file

**Modified**:
- `crates/bondnet-client/src/lib.rs` — export new modules
- `crates/bondnet-client/src/main.rs` — `health-diag` subcommand
- `crates/bondnet-client/src/multipath.rs` — health tracker integration, 4 new tests
- `crates/bondnet-server/src/server.rs` — PathKeepalive echo, `keepalive_echo_errors` metric, `record_packet` fix (don't overwrite remote_addr for keepalive)
