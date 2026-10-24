# BondNet Day 21 — Test Guide (Make It Actually Work)

Day 21 was an audit + verification milestone. No code changes were needed:
the Day 20 wiring was re-audited line by line and then proven with the real
binaries on the real Windows machine. This guide is the shortest path to
reproduce every check, in order.

## What Day 21 proved (2026-10-24)

| Check | Where | Result |
|---|---|---|
| Full automated test suite | Sandbox | 335 passed / 0 failed / 2 ignored |
| Release build | Sandbox | PASS (47s) |
| Windows-target test check + fmt | Sandbox | PASS |
| Encrypted upload, real binaries, real UDP | His Windows (loopback) | 5/5 DATA decrypted by server |
| Wrong-PSK fail-closed, real binaries | His Windows (loopback) | 0 DATA accepted, all dropped |
| Real Linux TUN + encrypted return | — | NOT RUN (Docker Desktop was off) |
| Real Windows → VPS transport | — | NOT RUN (no VPS) |
| Real Internet traffic through tunnel | — | NOT RUN (no VPS) |
| Two physical paths + failover | — | NOT RUN (no VPS, no 2nd network) |

## Step 0 — Rebuild the release binaries (his machine, his shell)

The release binaries on the Windows machine are still the Day 19 build
(19-10-2026 15:57). Day 20/21 code is in the debug binaries (from the
19-10-2026 16:45 test run). Rebuild release once, in his own PowerShell:

```powershell
Set-Location "D:\Samrat Ujjwal\BondNet"
cargo build --release -j 2
cargo test --workspace -j 2
```

Expected: build succeeds; tests 333 passed / 0 failed / 1 ignored.

Note: cargo cannot be executed from Basanti's SSH session (the Rust
toolchain in D:\Rust refuses to start under that logon session:
"The system cannot execute the specified program"). App binaries run
fine over SSH; only the toolchain is affected. Builds stay a local step.

## Step 1 — Loopback encrypted transport test (real binaries)

Run in two PowerShell windows on the Windows machine. Test PSK (any 64 hex
chars; client and server must match):

```powershell
$psk = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
```

Window 1 — server:

```powershell
Set-Location "D:\Samrat Ujjwal\BondNet"
.\target\release\bondnet-server.exe --bind 127.0.0.1:51820 --psk $psk --verbose
```

Expected startup lines:

```text
encryption: ENABLED (XChaCha20-Poly1305, PSK from --psk)
server listening on 127.0.0.1:51820
```

Window 2 — client (correct PSK):

```powershell
Set-Location "D:\Samrat Ujjwal\BondNet"
.\target\release\bondnet-client.exe tunnel-smoke --local 127.0.0.1:40001 --remote 127.0.0.1:51820 --path-id 1 --session-id 42 --synthetic --synthetic-count 5 --psk $psk --verbose
```

Expected client output ends with `done: tunnel_packets_sent=5 ... send_errors=0`.
Expected server output (the proof — DATA_RX appears only after the server
decrypts the packet and validates the inner IP packet):

```text
RX session=42 path=1 seq=0 type=PathHello payload=32 remote=127.0.0.1:40001
DATA_RX session=42 path=1 seq=1 payload_len=64 ...
DATA_RX session=42 path=1 seq=2 payload_len=512 ...
DATA_RX session=42 path=1 seq=3 payload_len=1200 ...
DATA_RX session=42 path=1 seq=4 payload_len=1400 ...
DATA_RX session=42 path=1 seq=5 payload_len=1500 ...
```

Negative test — same client command with a wrong PSK
(`ffff...` 64 times) and `--session-id 43`: the client still sends, but the
server must print NO `DATA_RX` line for session 43. That is fail-closed
working. Stop the server with Ctrl+C when done.

## Step 2 — Linux TUN test in Docker (his machine)

Start Docker Desktop first (it was not running on Day 21), wait for the
engine, then follow `docs/day20-test-guide.md` — the VPS setup section is
written for a real Linux host; inside Docker the same server binary runs
with `--tun-name bondtun0 --tun-addr 10.200.0.1 --tun-prefix 24
--tun-return-session 42 --tun-return-path 1 --psk $psk`, which additionally
proves the encrypted return path (server TUN → client) with real kernels.
The Day 10 Docker result (plaintext, 5/5 packets byte-matched) is the
baseline this extends.

## Step 3 — Real VPS test (blocked — exactly what is missing)

Not runnable yet. Required, all of it:

1. A Linux VPS (Ubuntu 24.04) reachable on a public IP, with root/sudo SSH.
2. UDP port 51820 open inbound on the VPS.
3. Permission to create a TUN device, enable `net.ipv4.ip_forward=1`, and
   add MASQUERADE + FORWARD iptables rules (commands in
   `docs/day20-test-guide.md`, VPS setup section — nothing else changes).
4. The Windows client keeps its default route and DNS untouched; the guide
   uses one explicit, reversible test route (`route add 1.1.1.1 ...`) with
   its delete command printed next to it.

With those four, the Day 20 guide's 10-step procedure runs as written:
server start → PathHello (payload=32) → encrypted upload visible in
`tcpdump -i bondtun0` → encrypted return → Internet ping through the
tunnel → second path → failover → recovery → bench.

## Known limitations (unchanged from Day 20)

- No multipath client binary yet: `tunnel-smoke` drives one `UdpPath`;
  `MultipathDataPlane` + `HealthMonitor` are implemented and unit-tested
  but not hosted in a shipped binary.
- Manual PSK, no handshake, no forward secrecy.
- No MTU/MSS clamping: 1500-byte inner packets + 36-byte header + 16-byte
  tag can fragment on a 1500-MTU path.
- Single server return association per (session, path).
