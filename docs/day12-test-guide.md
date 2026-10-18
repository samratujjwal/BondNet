# BondNet Day 12 — End-to-End Test Guide

Levels A–D, in strict order. Do not mark a higher level passed because a
lower one passed.

---

## Addressing model (read before any real test)

| Endpoint              | Address      | Role                                              |
|-----------------------|--------------|---------------------------------------------------|
| VPS TUN (`bondtun0`)  | `10.200.0.1` | Tunnel gateway; kernel routes here for the subnet |
| Windows Wintun        | `10.200.0.2` | Client tunnel address (operator assigns)          |
| Tunnel subnet         | `10.200.0.0/24` | Private; must not overlap VPS LAN or home LAN  |

The client sends IP packets with source `10.200.0.2`. The VPS kernel
sees them arrive on `bondtun0`, routes them out the WAN interface with
NAT masquerade, and return traffic for `10.200.0.0/24` is routed back
into `bondtun0` by the connected route (installed when the address is
assigned). The server's TUN reader thread picks those packets up and
returns them over UDP.

Critical invariants:

- The VPS's **tunnel UDP transport** (port 51820) uses the physical
  network and the VPS's public address. It must NOT be routed into
  `bondtun0`. This holds automatically: the UDP socket is bound to the
  physical interface's address, and no route directs the client's public
  IP into the TUN device.
- The Windows **UDP transport** likewise uses the physical adapter and
  the VPS's public IP. Do not add a Windows route that sends the VPS's
  public IP into Wintun — that would recurse the tunnel through itself.
- Do NOT set a Windows default route or change DNS in Day 12. Test
  traffic is directed explicitly (e.g. `ping 10.200.0.1`, or an app
  bound to `10.200.0.2` talking to one controlled external IP).

---

## Level A — Automated (runs anywhere)

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace
```

Windows target (on any machine with the target installed):

```powershell
cargo check --workspace --target x86_64-pc-windows-msvc --tests
```

Ignored loopback tests (need real UDP sockets; sandbox blocks `sendto`):

```bash
cargo test --workspace -- --ignored
```

Deterministic e2e simulation (fake TUN / fake Wintun, real
encoder/decoder/validators — a logic proof, NOT a network proof):

```bash
cargo test -p bondnet-server --lib e2e_sim
```

Pass criteria: every command above exits 0. The simulation must show
both `e2e_sim_*` tests passing.

---

## Level B — Real Windows ↔ VPS transport

Prerequisites: VPS reachable at its public IP; UDP port 51820 open
inbound on the VPS firewall.

1. On the VPS:

   ```bash
   sudo ./bondnet-server --bind 0.0.0.0:51820 --verbose \
     --tun-name bondtun0 --tun-addr 10.200.0.1 --tun-prefix 24 \
     --tun-return-session 1001 --tun-return-path 1
   ```

2. On Windows (from the BondNet repo):

   ```powershell
   cargo run -p bondnet-client --bin tunnel-smoke -- `
     --local 0.0.0.0:0 --remote <VPS_PUBLIC_IP>:51820 `
     --path-id 1 --session-id 1001 --synthetic --return --verbose
   ```

3. Check the VPS log: `DATA_RX session=1001 path=1 seq=…` lines appear
   with increasing sequence numbers. The `remote=` must be the Windows
   machine's public address.

4. Return check (no TUN traffic yet): the client log must show return
   packets only after the server has something to send back. At this
   level, success = UDP flows both ways without errors; the server will
   log `RETURN_NO_ENDPOINT` until step 1's association sees traffic —
   after the first upload it should stop.

Pass criteria: bidirectional UDP works; session/path/sequence in the
VPS log match what the client sent; no panics on either side.

---

## Level C — Real Linux TUN

Prerequisites: Level B passes; VPS has `CAP_NET_ADMIN` (run as root or
with the capability); `iproute2` installed.

1. Safe pre-checks (read-only, run any time):

   ```bash
   ip -brief link
   ip -brief addr
   ip route get 1.1.1.1
   sysctl net.ipv4.ip_forward
   ```

   Required: `bondtun0` exists with `10.200.0.1/24`; `ip_forward` is `1`;
   `ip route get 1.1.1.1` shows a `dev <wan>` that is NOT `bondtun0`.

2. Assign the TUN address (after the server creates the device):

   ```bash
   sudo ip addr add 10.200.0.1/24 dev bondtun0
   sudo ip link set bondtun0 up
   ip route show 10.200.0.0/24   # expect: 10.200.0.0/24 dev bondtun0 scope link
   ```

3. Upload injection: from Windows, send the synthetic packet (Level B
   command). On the VPS, per packet:

   ```text
   DATA_RX session=1001 path=1 seq=N payload_len=… fp=…
   TUN_TX dev=bondtun0 len=…
   ```

   And the kernel must see it:

   ```bash
   ip -s link show bondtun0   # RX packets/bytes grow with TUN_TX
   ```

4. Return read: craft a reply into the TUN device from the VPS itself.
   The simplest controlled packet is an ICMP echo reply to a request
   the client sent, but for Level C a synthetic IP packet is enough:

   ```bash
   # Python one-liner: write a 64-byte IPv4 packet (src 10.200.0.1,
   # dst 10.200.0.2) into /dev/net/tun via the bondtun0 fd is not
   # trivial from shell — use the server's verbose log instead:
   ```

   Practical approach: run `ping -I bondtun0 10.200.0.2` on the VPS.
   The echo requests enter `bondtun0` from the kernel side, the
   server's reader thread picks them up, and — because the return
   association points at the Windows client — they are sent back as
   BondNet DATA. The Windows client (with `--return`) validates and
   writes them to Wintun. Watch for:

   ```text
   RETURN_TX session=1001 path=1 seq=1 payload_len=64 remote=<windows>
   ```

   on the VPS, and a matching receive on Windows.

Pass criteria: `TUN_TX` lines correlate 1:1 with `ip -s link` RX
growth; `RETURN_TX` fires for kernel-originated packets; fingerprints
match where checked.

---

## Level D — Real Internet forwarding

Prerequisites: Level C passes; NAT masquerade + FORWARD rules in place
(see `docs/vps-day10-setup.md` §§4–5 — append-only, scoped to
`10.200.0.0/24` and the WAN interface; never flush existing rules).

1. From Windows, generate traffic with source `10.200.0.2` and a
   **single controlled destination**, e.g.:

   ```powershell
   ping 10.200.0.1        # tunnel-local: must work before Internet
   ping 1.1.1.1           # Internet: needs NAT + return path
   ```

   (For `ping 1.1.1.1` to use the tunnel, Windows must route it via
   Wintun: `route add 1.1.1.1 mask 255.255.255.255 10.200.0.1` —
   temporary, host-only, remove afterwards with `route delete 1.1.1.1`.
   Do NOT add a default route.)

2. Expected chain per echo request:

   ```text
   Windows ping → Wintun → client DATA → VPS DATA_RX → TUN_TX →
   kernel → NAT → Internet → reply → kernel → bondtun0 →
   RETURN_TX → client → Wintun → Windows ping reply
   ```

3. Verify each hop: `DATA_RX`/`TUN_TX` on the VPS, `ip -s link`
   RX+TX growth on `bondtun0`, `RETURN_TX` with the reply, and the
   Windows `ping` reporting replies.

Pass criteria: `ping 1.1.1.1` through the tunnel gets replies;
removing the temporary route restores normal behavior. This is the
first genuine Internet proof — everything before it is transport
and injection.

---

## MTU notes

- Inner IP packet limit: **1500 bytes** (`MAX_WINTUN_PACKET_LEN`).
- BondNet header: **36 bytes**. Maximum UDP datagram: **1536 bytes**.
- A 1536-byte UDP datagram exceeds the common 1500-byte path MTU and
  may be IP-fragmented on the physical path. Fragmentation works but
  is fragile (one lost fragment kills the datagram).
- Day 12 does not add fragmentation or MTU discovery. If the physical
  path has a smaller MTU, lower the inner limit accordingly (code
  change, not a runtime flag — document the value used).
- No MTU/MSS clamping is implemented yet; TCP through the tunnel may
  need it later (Day 13+).

---

## Safety rules (all levels)

- Test only against a VPS you administer. The protocol is plaintext
  and unauthenticated — never expose the port beyond your test client.
- Appendix commands only; never flush firewall rules.
- Temporary Windows routes are host-scoped (`mask 255.255.255.255`)
  and must be deleted after the test.
- Never log keys or full packet contents; fingerprints only.
