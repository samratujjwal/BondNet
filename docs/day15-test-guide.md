# BondNet Day 15 — Ordering Test Guide

Day 15 implements session-wide logical sequences and bounded reorder
buffers for both upload and return directions.

---

## Logical vs per-path sequences

**Before Day 15**: each `UdpPath` had its own counter (path 1: 1,2,3;
path 2: 1,2). There was no way to order packets across paths.

**Day 15**: the `sequence` header field is the session-wide logical
order per direction. The client allocates 1,2,3,4,5... from a single
`AtomicU64` before choosing a path. The `path_id` says which path
carried it; the `sequence` says where it belongs in the session.

The 36-byte header layout is unchanged. This is a semantic change, not
a wire-format change.

## Session and direction scope

- **Upload**: one counter per client session (`DataPlane` or
  `MultipathDataPlane`). Starts at 1.
- **Return**: one counter per server session (`SessionState`).
  Starts at 1.
- The two counters are independent. Session 1001's upload seq 5 and
  return seq 5 are unrelated.
- Different sessions have different counters.

## Where sequences are allocated

- **Upload**: `DataPlane::send_wintun_packet` or
  `MultipathDataPlane::send_wintun_packet` calls
  `upload_sequence.fetch_add(1, SeqCst)` BEFORE path selection.
  The sequence is passed to `UdpPath::send_new`.
- **Return**: `Server::process_return_packet` (via
  `build_return_datagram`) allocates from the session's
  `return_sequence` under the registry lock.

`UdpPath` never allocates sequences. Control packets use a diagnostic
sequence (not ordered).

## Where reordering occurs

- **Upload** (VPS): `Server::forward_to_tun` pushes validated DATA
  packets into a per-session `OrderedReceiver`. Contiguous packets go
  to the TUN queue in order.
- **Return** (Windows): `return_receiver_loop` pushes validated return
  DATA into an `OrderedReceiver`. Contiguous packets go to the Wintun
  channel in order.

Only `PacketType::Data` enters the buffer. Validation (protocol,
session, path, IP) happens BEFORE buffering.

## Timeout/gap policy

If sequence N is missing, sequences N+1, N+2... stay buffered. After
200ms with no progress, the buffer skips the gap: N is abandoned as
loss, and the buffered packets are released.

**Implications**: skipping is loss, not recovery. TCP will see a gap
and (if the connection survives) retransmit. This policy prevents a
single lost packet from stalling the tunnel forever. It does NOT
provide reliable delivery.

## Duplicate, late, overflow handling

- **Duplicate** (seq already buffered): dropped, counted. Never
  delivered twice.
- **Late** (seq < next_expected): dropped, counted. The frontier never
  moves backwards.
- **Overflow** (buffer full, 256 packets): newest packet dropped,
  counted. Memory stays bounded.

## Buffer limits and metrics

- Max 256 out-of-order packets per session per direction.
- Timeout 200ms per gap.
- Server stats: `upload_ordered_delivered`, `upload_gaps`,
  `upload_gap_timeouts`, `upload_duplicates_dropped`,
  `upload_late_dropped`, `upload_overflow_dropped`.
- Client return metrics are in the `OrderedReceiver` (accessible via
  `metrics_snapshot`).

## Header compatibility

The 36-byte header is unchanged. Field offsets, sizes, and encoding are
identical. The `sequence` field's SEMANTICS changed from "per-path" to
"per-session-per-direction". Old clients/servers that expect per-path
sequences will interoperate at the wire level but ordering will be
incorrect. This is a coordinated upgrade (both ends must be Day 15+).

## What tests prove

- In-order packets deliver immediately (no buffering delay).
- Arrival 1,3,2 emits 1,2,3.
- Packets on different paths reorder by logical sequence.
- Duplicates emitted at most once.
- Late packets dropped.
- Invalid session/path/type packets don't corrupt the buffer.
- Overflow stays bounded (256 max).
- A missing packet cannot block forever (200ms timeout).
- Upload and return sequences are independent.
- Concurrent allocation produces no duplicates (AtomicU64).
- Control packets bypass the reorder buffer.
- Payload bytes are bit-exact through the buffer.
- Single-path mode still works (all Day 1-14 tests green).

## What still requires real validation

- Two physical networks delivering out-of-order packets to the VPS,
  verifying the TUN receives them in order.
- Return path ordering with real Wintun on Windows.
- Timeout behavior under real packet loss (not simulated).
- Performance: buffer overhead at line rate.
- The 200ms timeout may need tuning for high-latency paths.

Do not claim end-to-end multipath ordering is proven by unit tests
alone.
