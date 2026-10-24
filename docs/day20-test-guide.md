# BondNet Day 20 Test Guide — Final Working Application & End-to-End Readiness

## What Day 20 Changed

Day 20 is a **wiring milestone**: the crypto, health, and multipath
components from Days 17–19 existed but were never connected to the real
binaries. This day connects them.

### Fixed blockers

| # | Blocker | Fix |
|---|---------|-----|
| 1 | Client had no `--psk` flag — encryption was dead code | `--psk HEX` added to `bondnet-client` (default mode), `tunnel-smoke`, and `path-diag` |
| 2 | `set_secure_session` never called anywhere | Wired in all three client modes; `ReturnProcessor` gets the session for return decryption |
| 3 | Client never sent the session salt | `PathHello` payload now carries the 32-byte salt when `--psk` is set |
| 4 | `tunnel-smoke` Wintun mode never sent `PathHello` | Sends `PathHello` (with salt) before any DATA |
| 5 | Return receiver used plaintext `validate` | Uses `validate_decrypted` (authenticates + decrypts when a session is set; identical behavior otherwise) |
| 6 | Server TUN reader thread passed `None` (plaintext return) | Reader looks up the session per packet and encrypts return DATA |
| 7 | Stale "plaintext (no encryption yet)" warnings | Warnings now reflect reality: shown only when `--psk` is absent |
| 8 | `PathKeepalive` fully plaintext, forgeable | Probes encrypted (`UploadControl`), echoes encrypted (`ReturnControl`); forged/tampered probes get no echo and increment `auth_failures` |
| 9 | `MultipathDataPlane::set_secure_session` stored but never propagated | Documented: no binary currently drives Wintun through the multipath plane (see Limitations) |

### What was NOT changed

Working components were left alone: scheduler, reorder buffer, Wintun
bindings, TUN reader/writer threads, shutdown sequencing, config
validation. The `--psk` parsing on the server is unchanged.

---

## Test levels (read this first)

| Level | What it proves | Status |
|-------|----------------|--------|
| A. Automated unit/integration tests | Crypto, protocol, scheduling, auth logic | **PASS** — 335 tests, run below |
| B. Loopback simulation | Client↔server packet flow on one machine | Possible — see §5 |
| C. Real Windows → VPS transport | Encrypted tunnel over the Internet | **NOT RUN** — needs your VPS |
| D. Real Internet forwarding | Browsing / ping through the tunnel | **NOT RUN** — needs your VPS |
| E. Real multi-physical-network bonding | Two independent ISPs bonded | **NOT RUN** — needs hardware |

Never mark C/D/E passed without actually running them.

---

## 1. Linux VPS setup

### 1.1 Prerequisites

- Ubuntu 24.04 (or similar), root/sudo access.
- Rust toolchain: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- The BondNet repository (clone or copy the `BondNet` directory).

### 1.2 Build

```bash
cd BondNet
cargo build --release -p bondnet-server
# Binary: ./target/release/bondnet-server
```

### 1.3 Generate a PSK (do this once, keep it secret)

```bash
# 32 random bytes as 64 hex chars:
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Save it somewhere safe (password manager). **Never commit it, never
paste it into logs or chat.** Both the server and the client need the
identical value.

### 1.4 Network setup (every boot, or persist it)

Follow `docs/vps-day10-setup.md`. Short version:

```bash
# IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Discover the WAN interface (never assume eth0):
ip route get 1.1.1.1
# → note the "dev <name>"

# NAT (replace eth0 with your WAN interface):
sudo iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -o eth0 -j MASQUERADE

# FORWARD chain only if the default policy is DROP:
sudo iptables -S FORWARD | head -3
# if DROP:
sudo iptables -A FORWARD -i bondtun0 -o eth0 -s 10.200.0.0/24 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o bondtun0 -d 10.200.0.0/24 \
  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

**Safety:** append (`-A`) only, never flush. Scope every rule to the
tunnel subnet. These commands do not touch the VPS's SSH access.

### 1.5 Start the server

```bash
sudo ./target/release/bondnet-server \
  --tun-name bondtun0 --tun-addr 10.200.0.1 --tun-prefix 24 \
  --tun-return-session 1001 --tun-return-path 1 \
  --psk <64-hex-chars> \
  --verbose
```

Expected output:

```text
encryption: ENABLED (XChaCha20-Poly1305, PSK from --psk)
server listening on 0.0.0.0:51820
TUN return path enabled: device bondtun0 -> session=1001 path=1
```

Then, in another shell (the server does not assign the address itself):

```bash
sudo ip addr add 10.200.0.1/24 dev bondtun0
sudo ip link set bondtun0 up
ip addr show bondtun0   # verify 10.200.0.1/24 is present
```

Keep the server's terminal visible — `--verbose` logs every packet.

### 1.6 Stopping / cleanup

Ctrl+C in the server terminal. The TUN device is destroyed
automatically. To remove the NAT rule later:

```bash
sudo iptables -t nat -D POSTROUTING -s 10.200.0.0/24 -o eth0 -j MASQUERADE
```

---

## 2. Windows client setup

### 2.1 Prerequisites

- Windows 10/11 64-bit, Administrator terminal (PowerShell as Admin).
- Rust toolchain (https://rustup.rs) — MSVC build tools included.
- `wintun.dll` next to the client binary (download from
  https://www.wintun.net; the client loads it at runtime).
- The BondNet repository at `D:\Samrat Ujjwal\BondNet`.

### 2.2 Build

```powershell
cd "D:\Samrat Ujjwal\BondNet"
cargo build --release -p bondnet-client
# Binary: .\target\release\bondnet-client.exe
```

### 2.3 Find your physical interface address

```powershell
ipconfig
```

Pick the IPv4 address of the adapter your Internet uses (e.g. Wi-Fi:
`192.168.1.50`). The tunnel socket binds this address — that is what
pins tunnel UDP to the physical interface and avoids routing recursion.

### 2.4 Start the client (single path, Wintun, encrypted)

```powershell
.\target\release\bondnet-client.exe tunnel-smoke `
  --local 192.168.1.50:0 `
  --remote <VPS-PUBLIC-IP>:51820 `
  --path-id 1 --session-id 1001 `
  --adapter BondNet `
  --return `
  --psk <same-64-hex-chars> `
  --verbose
```

Expected output:

```text
encryption: ENABLED (XChaCha20-Poly1305, session salt exchanged via PathHello)
Wintun DLL: loaded
Adapter: BondNet (opened or created)
Tunnel UDP: 192.168.1.50:<port> -> <VPS>:51820 (physical interface)
PathHello sent seq=0
Session: started (ring capacity ...)
Reading Wintun packets... (Ctrl+C to stop)
Return path enabled: UDP -> validate -> Wintun
```

**Do NOT add routes yet.** First verify the tunnel works (see §3).
BondNet never replaces your default route automatically; any routing
change is a manual, explicit step in §4.

### 2.5 Stopping

Ctrl+C. The client joins the Wintun reader thread, drains the sender,
awaits the return task, closes the adapter, and exits. You should see:

```text
tunnel-smoke done: wintun_packets_read=... tunnel_packets_sent=... ...
return done: packets_received=... ...
Adapter: closed
Exiting cleanly.
```

---

## 3. Ordered end-to-end test procedure

Do these in order. Each step gates the next.

### Step 1 — Server is listening

On the VPS:

```bash
ss -ulpn | grep 51820
```

Expect: a UDP socket on `0.0.0.0:51820`. If absent, the server did not
start — check its terminal for the bind error.

### Step 2 — Client establishes the session

Start the client (§2.4). On the **server** terminal you must see:

```text
RX session=1001 path=1 seq=0 type=PathHello payload=32 remote=<your-ip>:<port>
```

`payload=32` is the session salt. If you see `payload=0`, the client
did not send `--psk` — stop and fix the command line.

### Step 3 — Encrypted upload reaches the VPS TUN

On Windows, generate traffic that enters the Wintun adapter (after
§4 routing) — or first do the quick synthetic check:

```powershell
.\target\release\bondnet-client.exe tunnel-smoke `
  --local 192.168.1.50:0 --remote <VPS>:51820 `
  --path-id 1 --session-id 1001 `
  --synthetic --synthetic-count 5 `
  --psk <hex> --verbose
```

On the server:

```text
DATA_RX session=1001 path=1 seq=1 payload_len=... fp=... remote=...
```

`payload_len` here is the *decrypted* inner packet — the server only
logs after successful authentication. Then verify the TUN device got
it:

```bash
# on the VPS, in another shell:
sudo tcpdump -i bondtun0 -n -c 5
```

You must see the inner packets arriving on `bondtun0`.

**Negative check:** run the client *without* `--psk` (or with a wrong
PSK) against the `--psk` server. The server must show no `DATA_RX`
lines and its counters must show `auth_failures` increasing. The
packets are dropped before TUN — never forwarded.

### Step 4 — Return traffic reaches Windows Wintun

With `--return` on the client and `--tun-return-session 1001
--tun-return-path 1` on the server:

On the VPS, inject a packet into the tunnel subnet toward the client:

```bash
# The client will own 10.200.0.2 (assign it on Windows, §4):
ping -c 3 10.200.0.2
```

On the server terminal:

```text
RETURN_TX session=1001 path=1 seq=1 payload_len=... remote=<your-ip>:<port>
RETURN_UDP remote=<your-ip>:<port> bytes=...
```

On the client terminal:

```text
return received inner=...B seq=1
```

If `return packet rejected` appears, the return path failed
authentication — check the PSK matches on both ends.

### Step 5 — Internet connectivity through the tunnel (Level D)

**Explicit, reversible routing change.** In an Admin PowerShell:

```powershell
# Give Wintun its tunnel address:
netsh interface ip set address "BondNet" static 10.200.0.2 255.255.255.0

# Route ONLY a test target through the tunnel (not the default route):
route add 1.1.1.1 mask 255.255.255.255 10.200.0.1
```

Then:

```powershell
ping 1.1.1.1
```

What must happen: ICMP goes Windows → Wintun → encrypted tunnel →
VPS `bondtun0` → NAT → Internet → back → VPS → encrypted return →
Wintun → Windows. Watch both terminals for `DATA_RX` / `RETURN_TX`.

**Recovery (run when done testing):**

```powershell
route delete 1.1.1.1
netsh interface ip set address "BondNet" dhcp
```

Verify: `route print | Select-String "1.1.1.1"` shows nothing.

### Step 6 — Two physical paths (Level E, if hardware allows)

You need two genuinely independent uplinks (e.g. Wi-Fi + phone USB
tethering), each with its own local IPv4 address.

```powershell
# Terminal 1 (path 1 over Wi-Fi):
.\target\release\bondnet-client.exe tunnel-smoke --local 192.168.1.50:0 `
  --remote <VPS>:51820 --path-id 1 --session-id 1001 --adapter BondNet `
  --return --psk <hex>

# Terminal 2 (path 2 over tethered phone):
.\target\release\bondnet-client.exe tunnel-smoke --local 192.168.42.10:0 `
  --remote <VPS>:51820 --path-id 2 --session-id 1001 --adapter BondNet2 `
  --return --psk <hex>
```

Or use `path-diag` for a quick two-path handshake check:

```powershell
.\target\release\bondnet-client.exe path-diag --session-id 1001 `
  --path1-id 1 --path1-local 192.168.1.50:0 --path1-remote <VPS>:51820 `
  --path2-id 2 --path2-local 192.168.42.10:0 --path2-remote <VPS>:51820 `
  --psk <hex> --verbose
```

Server must log `RX ... type=PathHello payload=32` for **both** path 1
and path 2, from **different** remote ports.

**Honesty note:** two sockets on the same Wi-Fi adapter are two
*logical* paths, not two Internet connections. Only genuinely separate
uplinks prove bonding.

### Step 7 — Failover: disable one path

With both paths up (Step 6), disconnect one uplink (unplug / disable
the adapter). Traffic must continue over the surviving path. The
health monitor (1s heartbeat, 2 misses → Degraded, 3 → Unhealthy)
stops scheduling onto the dead path.

> Current limitation: the `tunnel-smoke` binary runs one path per
> process and does not yet host the `HealthMonitor`/multipath
> scheduler. Failover across paths today is observed at the *server*
> (per-path `last_seen`, `return_no_endpoint` counters) and in the
> `health-diag` simulation — not as automatic client-side
> re-scheduling inside one process. See §6 Limitations.

### Step 8 — Recovery: restore the path

Re-enable the uplink. `PathHello`/traffic resumes; the server's
per-path `last_seen` refreshes. Verify with the server's verbose log.

### Step 9 — Throughput / loss / errors

```powershell
.\target\release\bondnet-client.exe bench --help
```

Run the Day 16 benchmark against the real VPS (not loopback) to
measure single- vs dual-path throughput. Compare with the loopback
numbers from Day 16 (single 1355 Mbps > dual on loopback — expected;
real networks differ).

### Step 10 — Cleanup

1. Ctrl+C both clients; confirm `Adapter: closed` / `Exiting cleanly.`
2. Ctrl+C the server.
3. Remove the test route (§3 Step 5 recovery).
4. Optionally remove the NAT rule (§1.6).

---

## 4. Diagnostics & troubleshooting

### Client

| Symptom | Likely cause | Check |
|---------|--------------|-------|
| `Wintun DLL: failed to load` | `wintun.dll` missing | Place it next to the `.exe` |
| `WARNING: bound local IP ... differs` | `--local` IP not owned by this machine | `ipconfig`; use the real adapter IP |
| No `RX` on server | Firewall / wrong VPS IP / server not listening | `Test-NetConnection <VPS> -Port 51820 -InformationLevel Detailed` (UDP is connectionless; check server log instead) |
| `return packet rejected: ...` | PSK mismatch | Both sides must use the identical 64-hex PSK |
| `invalid --psk` | Wrong length / non-hex | Must be exactly 64 hex chars |

### Server

| Symptom | Likely cause | Check |
|---------|--------------|-------|
| `auth_failures` climbing | Wrong PSK on client, or tampering | Compare PSKs; check `payload=32` on PathHello |
| `DATA_RX` but nothing on `bondtun0` | Invalid inner IP | `tun_invalid_ip` counter; client must send real IP packets |
| `RETURN_NO_ENDPOINT` | No Data/PathHello seen yet, or association expired | Send traffic first; check `--tun-return-session/--tun-return-path` match the client |
| `keepalive_echo_errors` | Client unreachable on the probe socket | Normal during path outages |

### Counters worth watching (server, end of run)

The server prints final counters on shutdown. Key ones:

- `datagrams_received` / `valid_packets` / `malformed_packets`
- `data_packets` / `data_bytes`
- `auth_failures` — must be 0 in a clean run
- `tun_packets_written` — packets actually delivered to the kernel
- `return_packets_sent` / `return_no_endpoint`

---

## 5. Quick loopback check (no VPS needed, Level B)

On one machine, run the server (no TUN needed) and the synthetic
client against `127.0.0.1`:

```bash
# Terminal 1 (Linux or WSL):
./target/release/bondnet-server --psk <hex> --verbose
```

```powershell
# Terminal 2 (Windows):
.\target\release\bondnet-client.exe tunnel-smoke --local 127.0.0.1:0 `
  --remote 127.0.0.1:51820 --path-id 1 --session-id 1001 `
  --synthetic --synthetic-count 5 --psk <hex> --verbose
```

Expect `DATA_RX` lines on the server. This proves the encrypted
pipeline without any network. (Sandbox note: the build VM blocks UDP
`sendto` even on loopback, so this check needs a real machine.)

---

## 6. Known limitations (Day 20)

1. **No automatic multipath client binary yet.** `MultipathDataPlane`
   (scheduler), `HealthMonitor` (failover), and `PathManager` are
   implemented and unit-tested, and keepalive authentication is now
   wired into them — but `tunnel-smoke` drives a single `UdpPath`.
   Running bonded multi-path through one process is the next
   integration step.
2. **Keepalive monitor not hosted in `tunnel-smoke`.** Probes/echoes
   are authenticated end-to-end (tested), but no shipped binary
   currently starts the `HealthMonitor` loop.
3. **Manual PSK, no handshake, no forward secrecy.** Anyone holding
   the PSK can decrypt past traffic. Rotate the PSK if exposed.
4. **No MTU/MSS clamping.** Inner 1500 B + 36 B header + 16 B tag can
   exceed path MTU and fragment. Watch for loss on real networks.
5. **Single return association.** The server returns via one
   configured `(session, path)`; per-path return selection is future
   work.
6. **Windows-only Wintun path.** The Wintun data path needs Windows;
   `--synthetic` is the portable smoke test.
7. **Levels C–E never run by the developer.** All real-network claims
   above are procedures for you, not results.

---

## 7. What to send back

After running the steps above, send:

1. The server terminal log (or at least the `RX`/`DATA_RX`/
   `RETURN_TX` lines and final counters).
2. The client terminal log.
3. Which steps passed / failed, and the exact error text for failures.
4. `cargo test --workspace -j 2` output (expect 335 passed).
