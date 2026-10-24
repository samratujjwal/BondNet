# BondNet Day 22 — VPS Deployment Guide

Copy-pasteable deployment for a **fresh Ubuntu VPS** + the existing Windows
client. Every flag below was verified against the actual Day 20/21/22 code.
Placeholders — replace them, never invent real values in shared logs:

- `<VPS_IP>` — the VPS public IPv4 address
- `<PSK_HEX>` — 64 hex chars, generated in step A3, identical on both ends
- Session `1001`, path `1`, tunnel subnet `10.200.0.0/24` (VPS `.1`, client `.2`)

Status honesty box (Day 22, 2026-10-24): the server was built natively on
Linux and run with a real TUN device (startup, kernel packets into the
reader, clean shutdown all verified). The encrypted UDP leg between two
real processes was verified on Windows loopback (Day 21). A test against a
real public VPS has **NOT** run yet — this guide is the procedure for it.

---

## Part A — VPS (Ubuntu 24.04, root or sudo)

### A1. Dependencies and source

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config curl git tcpdump
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Get the code (clone the repo, or copy the `BondNet` folder up with `scp -r`):

```bash
git clone <your-repo-url> BondNet
cd BondNet
```

Alternative: build on any Linux x86_64 machine
(`cargo build --release -p bondnet-server`) and `scp
target/release/bondnet-server` to the VPS. Building on the VPS itself is
preferred — no glibc mismatch surprises.

### A2. Build the Linux server

```bash
cargo build --release -p bondnet-server
ls -la target/release/bondnet-server
```

Do **not** copy the Windows `bondnet-server.exe` to Linux — different binary.

### A3. Generate the PSK (once, keep it secret)

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Store the output in a password manager. Never commit it, never paste it
into logs, tickets, or chat. The Windows client needs the identical value.

### A4. Firewall (only what BondNet needs)

```bash
sudo ufw allow 22/tcp
sudo ufw allow 51820/udp
sudo ufw enable
sudo ufw status
```

SSH (22) stays open first so you cannot lock yourself out. BondNet needs
exactly one inbound UDP port: **51820**.

### A5. Forwarding and NAT

```bash
# Forwarding (runtime + persistent):
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-bondnet.conf
sudo sysctl -w net.ipv4.ip_forward=1

# Find the WAN interface — never assume eth0:
ip route get 1.1.1.1
# note the "dev <name>" in the output; call it <WAN> below.

# NAT for the tunnel subnet only (append, never flush):
sudo iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -o <WAN> -j MASQUERADE

# Only if FORWARD policy is DROP (check: sudo iptables -S FORWARD):
sudo iptables -A FORWARD -i bondtun0 -o <WAN> -s 10.200.0.0/24 -j ACCEPT
sudo iptables -A FORWARD -i <WAN> -o bondtun0 -d 10.200.0.0/24 \
  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

The server also prints a setup guide for its own configuration:

```bash
./target/release/bondnet-server --tun-name bondtun0 --tun-addr 10.200.0.1 \
  --tun-prefix 24 --print-setup
```

### A6. Start the server

```bash
sudo ./target/release/bondnet-server \
  --bind 0.0.0.0:51820 \
  --tun-name bondtun0 --tun-addr 10.200.0.1 --tun-prefix 24 \
  --tun-return-session 1001 --tun-return-path 1 \
  --psk <PSK_HEX> \
  --verbose
```

Expected startup (verified on native Linux, Day 22):

```text
encryption: ENABLED (XChaCha20-Poly1305, PSK from --psk)
server listening on 0.0.0.0:51820
TUN device bondtun0 opened (forwarding enabled, subnet 10.200.0.0/24)
TUN return path enabled: device bondtun0 -> session=1001 path=1
TUN reader started (bondtun0)
```

If you instead see `WARN net.ipv4.ip_forward is 0`, step A5 was skipped —
forwarded packets will not reach the Internet until it is fixed.

In a second SSH session, give the TUN device its address (the server
creates the device; it does not assign the address):

```bash
sudo ip addr add 10.200.0.1/24 dev bondtun0
sudo ip link set bondtun0 up
ip -brief addr show bondtun0
ss -ulpn | grep 51820
```

Optional — run it as a service instead of a terminal:

```ini
# /etc/systemd/system/bondnet.service
[Unit]
Description=BondNet server
After=network-online.target

[Service]
WorkingDirectory=/root/BondNet
ExecStart=/root/BondNet/target/release/bondnet-server --bind 0.0.0.0:51820 --tun-name bondtun0 --tun-addr 10.200.0.1 --tun-prefix 24 --tun-return-session 1001 --tun-return-path 1 --psk <PSK_HEX> --verbose
ExecStartPost=/bin/sh -c "sleep 1; ip addr add 10.200.0.1/24 dev bondtun0; ip link set bondtun0 up"
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bondnet
journalctl -u bondnet -f
```

### A7. Stop / clean up

Terminal: Ctrl+C. Service: `sudo systemctl stop bondnet`. The TUN device
is destroyed automatically on exit (verified Day 22). Remove NAT later
with the matching delete:

```bash
sudo iptables -t nat -D POSTROUTING -s 10.200.0.0/24 -o <WAN> -j MASQUERADE
```

---

## Part B — Windows client

### B1. Build and the Wintun DLL

```powershell
Set-Location "D:\Samrat Ujjwal\BondNet"
cargo build --release -j 2
```

`wintun.dll` (from https://www.wintun.net) must sit next to
`target\release\bondnet-client.exe`.

### B2. Find the physical interface IPv4

```powershell
ipconfig
```

Use the address of the adapter that carries your Internet (e.g. Wi-Fi
`192.168.1.50`). Binding `--local` to it pins the tunnel UDP to the
physical path — this is what prevents routing recursion. **BondNet never
changes your default route or DNS.**

### B3. First contact check (synthetic, no Wintun, no routes)

```powershell
.\target\release\bondnet-client.exe tunnel-smoke `
  --local 192.168.1.50:0 --remote <VPS_IP>:51820 `
  --path-id 1 --session-id 1001 `
  --synthetic --synthetic-count 5 `
  --psk <PSK_HEX> --verbose
```

Server terminal must show:

```text
RX session=1001 path=1 seq=0 type=PathHello payload=32 remote=<your-public-ip>:<port>
DATA_RX session=1001 path=1 seq=1 payload_len=64 ...
... (5 DATA_RX lines)
```

`payload=32` = the session salt arrived. `DATA_RX` is logged only **after**
decryption + inner-IP validation. And on the VPS:

```bash
sudo tcpdump -i bondtun0 -n -c 5
```

must show the decrypted inner packets arriving on `bondtun0`.

Negative check: repeat with a wrong PSK. The server must log **no**
`DATA_RX` for that session and count the drops as `auth_failures`.

### B4. Full client (Wintun, encrypted, return path on)

Admin PowerShell:

```powershell
.\target\release\bondnet-client.exe tunnel-smoke `
  --local 192.168.1.50:0 --remote <VPS_IP>:51820 `
  --path-id 1 --session-id 1001 `
  --adapter BondNet `
  --return `
  --psk <PSK_HEX> --verbose
```

Expected: `encryption: ENABLED ...`, `PathHello sent seq=0`,
`Reading Wintun packets... (Ctrl+C to stop)`,
`Return path enabled: UDP -> validate -> Wintun`.

Return check from the VPS: `ping -c 3 10.200.0.2` (after B5 assigns the
address) → server logs `RETURN_TX session=1001 ...`, client logs
`return received inner=... seq=...`.

### B5. Internet test — one explicit, reversible route

Only after B3/B4 pass. Admin PowerShell:

```powershell
netsh interface ip set address "BondNet" static 10.200.0.2 255.255.255.0
route add 1.1.1.1 mask 255.255.255.255 10.200.0.1
ping 1.1.1.1
```

Watch both terminals: `DATA_RX` (up) and `RETURN_TX` (down) on the
server per ping. This routes only `1.1.1.1` through the tunnel — the
default route is untouched.

**Recovery (always run after the test):**

```powershell
route delete 1.1.1.1
netsh interface ip set address "BondNet" dhcp
route print | Select-String "1.1.1.1"   # must print nothing
```

### B6. Shutdown

Ctrl+C on the client: expect `Adapter: closed` and `Exiting cleanly.`
Ctrl+C on the server (or `systemctl stop`): expect `TUN reader stopped`,
`TUN writer stopped`, `server stopped`, and final counters with
`auth_failures = 0` in a clean run.

---

## Troubleshooting

| Symptom | Check |
|---|---|
| No `RX` on the server at all | VPS firewall: `ufw status` must list 51820/udp; cloud panel security group must also allow UDP 51820; server actually listening (`ss -ulpn`) |
| `RX ... payload=0` on PathHello | Client was started without `--psk` |
| PathHello arrives, no `DATA_RX` | PSK mismatch — compare both ends character by character; server counts `auth_failures` |
| `DATA_RX` but nothing in `tcpdump -i bondtun0` | Inner packets failing IP validation (`tun_invalid_ip` counter) — client is not sending real IP packets |
| Upload works, no `RETURN_TX` | `--tun-return-session/--tun-return-path` must match the client's `--session-id/--path-id`; association expires after 300 s idle (`--tun-return-max-age-secs`) — send traffic first |
| Ping 1.1.1.1 fails but B4 passed | `sysctl net.ipv4.ip_forward` must be 1; MASQUERADE rule must name the real WAN interface (`ip route get 1.1.1.1`) |
| Locked out of the VPS | Should not happen: no step touches port 22 or the default route. Use the provider's web console and re-check `ufw status` |
| Windows routing left broken | Run the B5 recovery block; BondNet itself never wrote any route |

## What remains after a successful deployment test

- Two physical paths + failover need a second genuine uplink on the
  Windows side and one `tunnel-smoke` process per path (the multipath
  scheduler/health monitor are library code, not yet a shipped binary).
- No MTU/MSS clamping yet: oversized inner packets can fragment on
  1500-MTU paths.
- Manual PSK only: no handshake, no forward secrecy. Rotate the PSK if
  it is ever exposed.
