# BondNet Day 16 — Benchmark Test Guide

Day 16 implements a deterministic, repeatable benchmark harness for
measuring local processing throughput and validating scheduler/ordering
correctness. It does NOT measure Internet bonding performance.

---

## What Day 16 implements

A `bench` subcommand for `bondnet-client` that exercises the REAL
`MultipathDataPlane` (scheduler + sequence allocation + packet encoding
+ UDP send) against local loopback receivers, and the REAL
`OrderedReceiver` with controlled input patterns.

**What is measured**: local packet processing throughput (encode, schedule,
send via loopback UDP), scheduler distribution accuracy, and reorder
buffer behavior.

**What is NOT measured**: Internet throughput, real physical interface
performance, VPS TUN throughput, or end-to-end bonding speedup.

## Benchmark commands

### Single-path baseline

```bash
cargo run -p bondnet-client --bin bondnet-client -- bench \
  --mode single \
  --packets 10000 \
  --payload-size 1200 \
  --repetitions 3
```

### Two-path equal weights

```bash
cargo run -p bondnet-client --bin bondnet-client -- bench \
  --mode dual-equal \
  --packets 10000 \
  --payload-size 1200 \
  --repetitions 3
```

### Two-path 3:1 weights

```bash
cargo run -p bondnet-client --bin bondnet-client -- bench \
  --mode dual-3to1 \
  --packets 10000 \
  --payload-size 1200 \
  --repetitions 3
```

### Custom weights

```bash
cargo run -p bondnet-client --bin bondnet-client -- bench \
  --weights 2,1,1 \
  --packets 5000 \
  --payload-size 1400 \
  --repetitions 5
```

### Arguments

- `--mode single|dual-equal|dual-3to1`: preset weight configurations.
- `--weights w1,w2,...`: custom weights (1-8 paths, each 1..1e9).
- `--packets N`: packets per repetition (1..10,000,000).
- `--payload-size B`: inner payload bytes (1..1500).
- `--repetitions R`: number of runs (1..100).

Invalid values are rejected with an error message. No randomness is
used; results are deterministic for a given machine and load.

## How to run each automated scenario

The 8 Phase-4 scenarios are unit tests in `bench.rs`:

```bash
# Config validation (scenarios 8: invalid config)
cargo test -p bondnet-client --lib bench::tests::config_

# Ordering scenarios (4-7: out-of-order, duplicates, gap timeout)
cargo test -p bondnet-client --lib bench::tests::ordering_

# All bench tests
cargo test -p bondnet-client --lib bench
```

Scenarios 1-3 (single, dual-equal, dual-3to1) are validated by the
benchmark runs above — check the `per-path` distribution in the output:
- single: `[N]` (all on path 1)
- dual-equal: `[N/2, N/2]` (within scheduler tolerance)
- dual-3to1: `[3N/4, N/4]` (within tolerance)

## How to interpret the metrics

### Throughput

- **Payload Mbps**: `(payload_bytes * 8) / elapsed_seconds / 1e6`.
  This is the inner IP payload throughput, excluding the 36-byte
  BondNet header.
- **Wire Mbps**: `((payload_bytes + header_bytes) * 8) / elapsed / 1e6`.
  Includes the 36-byte header per packet.
- **MiB/s**: payload bytes per second in mebibytes.

**Offered payload throughput** is what the benchmark tried to send.
**Wire throughput** includes protocol overhead. Neither is Internet
throughput.

### Distribution

`per-path: [500, 500]` means path 1 sent 500 packets, path 2 sent 500.
This proves the SCHEDULER chose each path that many times. It does NOT
prove packets traversed distinct physical interfaces — in the benchmark,
both paths use 127.0.0.1 loopback.

### Errors

- `send_errors`: UDP send failures (should be 0 on loopback).
- Reorder metrics (in ordering tests): gaps, timeouts, duplicates
  dropped, etc.

### Aggregate

Median/min/max across repetitions. A single run is not statistically
reliable — always use 3+ repetitions.

## Simulation vs loopback vs real VPS

| Level | What runs | What it proves |
|-------|-----------|----------------|
| **Unit** | Scheduler, OrderedReceiver in isolation | Algorithm correctness |
| **Loopback bench** | Real DataPlane + UDP to 127.0.0.1 | Processing throughput, distribution |
| **Real VPS** | Windows → Linux VPS over Internet | Actual bonding performance |

The Day 16 harness covers Unit and Loopback. Real VPS testing requires
your Windows machine and a Linux VPS — see below.

## Limitations and measurement error

1. **Loopback is not the Internet**: 127.0.0.1 has ~0 latency and no
   loss. Real networks have variable latency, loss, and reordering.
2. **Single machine**: both "paths" share the same CPU, NIC, and loopback.
   Real bonding uses distinct physical interfaces.
3. **No TUN involved**: the benchmark sends to UDP receivers, not through
   Wintun → TUN. TUN processing overhead is not measured.
4. **Timing noise**: other processes affect results. Use repetitions and
   report median.
5. **Debug vs release**: `cargo run` uses debug profile (slower). For
   serious numbers, use `cargo run --release`.

## Fair comparison procedure

To compare single-path vs multipath fairly:

1. Use the SAME `--packets`, `--payload-size`, and `--repetitions`.
2. Run each mode 3+ times.
3. Compare MEDIAN payload Mbps, not single runs.
4. Check `send_errors` is 0 (errors invalidate the comparison).
5. Remember: loopback multipath will NOT be 2x single-path — both share
   the same loopback interface. The benchmark validates CORRECTNESS
   (distribution follows weights), not speedup.

Example:
```bash
# Single-path baseline
cargo run -p bondnet-client --bin bondnet-client -- bench \
  --mode single --packets 10000 --payload-size 1200 --repetitions 3

# Multipath (expect ~same throughput on loopback, but 50/50 distribution)
cargo run -p bondnet-client --bin bondnet-client -- bench \
  --mode dual-equal --packets 10000 --payload-size 1200 --repetitions 3
```

## Real-network benchmark support

The current architecture supports real-network measurement WITHOUT
protocol changes:

**Available now**:
- Client: `MultipathDataPlane::metrics()` gives per-path packets/bytes
  sent, send errors. Log these periodically during a real test.
- Server: `Server::stats()` gives `upload_ordered_delivered`,
  `upload_gaps`, `upload_duplicates_dropped`, etc. Poll via a future
  admin endpoint or log at shutdown.
- The `path-diag` command verifies both paths are reachable.

**Not yet available**:
- The server cannot correlate a benchmark run ID with its counters
  (no run identifier in the protocol).
- There is no live query API for server stats (would need an admin
  socket or HTTP endpoint — not implemented).

**Minimal plan** (no protocol change):
1. On Windows: run `tunnel-smoke` with `--return` and log
   `MultipathDataPlane` metrics every second.
2. On VPS: run server with `--verbose`, capture logs. The
   `upload_ordered_delivered` counter shows TUN-bound packets.
3. Compare: client `packets_sent` vs server `upload_ordered_delivered`.
   The difference is loss + reorder drops.
4. For return: client return metrics vs server `return_packets_sent`.

Do NOT attempt Internet throughput tests without a real VPS and safe
configuration. Do not invent VPS addresses.

## What to send back after real-machine testing

After running on your Windows machine, send:

1. **The full benchmark output** for each mode (single, dual-equal,
   dual-3to1). Copy the entire terminal output, including the
   "Per-run results" and "Aggregate" sections.

2. **Your machine specs**: CPU, RAM, Windows version.

3. **For VPS tests** (if you run them):
   - Client: `packets_sent`, `send_errors` from the metrics log.
   - Server: `upload_ordered_delivered`, `upload_gaps`,
     `upload_duplicates_dropped` from server stats/logs.
   - The `path-diag` output showing both paths.

4. **Any errors or panics**: full error message and the command that
   produced it.

Do not summarize — send the raw output. I will analyze it.
