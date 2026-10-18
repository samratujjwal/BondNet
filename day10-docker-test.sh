#!/usr/bin/env bash
# ============================================================================
# BondNet Day 10 — one-shot TUN smoke test.
#
# Runs INSIDE the Ubuntu container. One file, one command, zero copy-paste
# chains: installs deps, builds, starts the server with TUN, runs the UDP
# probe, and prints a PASS/FAIL verdict with kernel counters.
#
# Exit code: 0 = all checks passed, 1 = something failed.
# ============================================================================
set -u
export DEBIAN_FRONTEND=noninteractive

# SKIP_SETUP=1 skips apt+rustup (they are already present). Used for re-runs
# and for testing the TUN/probe/verdict stages without reinstalling.
if [ "${SKIP_SETUP:-0}" != "1" ]; then
echo "=== [1/6] system packages ==="
apt-get update -qq
apt-get install -y -qq curl build-essential iproute2 iptables tcpdump python3
echo "packages OK"

echo "=== [2/6] Rust toolchain ==="
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y -q
fi
fi # SKIP_SETUP
export PATH="$HOME/.cargo/bin:$PATH"
cargo --version

echo "=== [3/6] build bondnet-server ==="
rm -rf ~/bondnet
cp -r /bondnet ~/bondnet
cd ~/bondnet
cargo build -p bondnet-server

echo "=== [4/6] start server with TUN ==="
rm -f /tmp/server.log /tmp/expect_fp.txt /tmp/got_fp.txt /tmp/tunstat.txt
./target/debug/bondnet-server --bind 0.0.0.0:51820 --verbose \
  --tun-name bondtun0 --tun-addr 10.200.0.1 --tun-prefix 24 > /tmp/server.log 2>&1 &
SRVPID=$!
sleep 1
if ! kill -0 $SRVPID 2>/dev/null; then
  echo "SERVER FAILED TO START — log:"
  cat /tmp/server.log
  exit 1
fi
ip addr add 10.200.0.1/24 dev bondtun0
ip link set bondtun0 up
echo "server pid=$SRVPID, bondtun0 up"

echo "=== [5/6] UDP probe ==="
python3 - 127.0.0.1 51820 <<'PYEOF'
import socket, struct, sys

HOST, PORT = sys.argv[1], int(sys.argv[2])
MAGIC = b'BN'
VERSION = 1
HLEN = 36
DATA = 1
PHELLO = 3

def fnv1a(data: bytes) -> int:
    h = 0xcbf29ce484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h

def encode(ptype, session, seq, path, payload):
    hdr = bytearray()
    hdr += MAGIC
    hdr += struct.pack('!BBH', VERSION, 0, HLEN)
    hdr += struct.pack('!Q', session)
    hdr += struct.pack('!Q', seq)
    hdr += struct.pack('!H', path)
    hdr += struct.pack('!BB', ptype, 0)
    hdr += struct.pack('!Q', 0)
    hdr += struct.pack('!H', len(payload))
    return bytes(hdr) + payload

def ipv4_packet(total_len, seed=0):
    # Minimal STRUCTURALLY-valid IPv4 packet: v4, IHL=5, total_len == len(buf).
    hdr = bytearray(20)
    hdr[0] = 0x45
    struct.pack_into('!H', hdr, 2, total_len)
    hdr[8] = 64
    hdr[9] = 1
    hdr[12:16] = bytes([10, 200, 0, 2])
    hdr[16:20] = bytes([1, 1, 1, 1])
    body = bytes(((i + seed) % 251 for i in range(total_len - 20)))
    return bytes(hdr) + body

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sizes = [64, 512, 1200, 1400, 1500]
fps = []
for i, sz in enumerate(sizes):
    p = ipv4_packet(sz, seed=i)
    fps.append(fnv1a(p))
    s.sendto(encode(DATA, 7, i, 1, p), (HOST, PORT))
    print(f"sent valid Data seq={i} len={sz} fp={fps[-1]:016x}", flush=True)

with open('/tmp/expect_fp.txt', 'w') as f:
    for fp in sorted(fps):
        f.write(f"{fp:016x}\n")

s.sendto(encode(DATA, 7, 100, 1, bytes(10)), (HOST, PORT))
print("sent invalid-IP Data seq=100 (expect IP_REJECT)", flush=True)

s.sendto(encode(PHELLO, 7, 101, 1, ipv4_packet(64)), (HOST, PORT))
print("sent PathHello seq=101 (expect RX only, no TUN_TX)", flush=True)

bad = bytearray(encode(DATA, 7, 102, 1, ipv4_packet(64)))
bad[0], bad[1] = 0x58, 0x58
s.sendto(bytes(bad), (HOST, PORT))
print("sent bad-magic datagram (expect WARN malformed)", flush=True)
s.close()
PYEOF

sleep 1

echo "=== [6/6] kernel TUN counters (read BEFORE shutdown) ==="
ip -s link show bondtun0 | tee /tmp/tunstat.txt

kill $SRVPID 2>/dev/null || true
wait $SRVPID 2>/dev/null || true

echo ""
echo "================ VERDICT ================"
pass=1

n_data=$(grep -c '^DATA_RX' /tmp/server.log || true)
n_tun=$(grep -c '^TUN_TX' /tmp/server.log || true)
n_rej=$(grep -c '^IP_REJECT' /tmp/server.log || true)
n_bad=$(grep -c 'WARN malformed' /tmp/server.log || true)
echo "DATA_RX lines : $n_data (expect 6: 5 valid + 1 invalid-IP Data)"
echo "TUN_TX lines  : $n_tun (expect 5)"
echo "IP_REJECT     : $n_rej (expect >= 1)"
echo "WARN malformed: $n_bad (expect >= 1)"
[ "$n_data" = "6" ] || pass=0
[ "$n_tun" = "5" ] || pass=0
[ "$n_rej" -ge 1 ] || pass=0
[ "$n_bad" -ge 1 ] || pass=0

# All 5 expected fingerprints must appear among DATA_RX lines (a 6th fp from
# the invalid-IP probe packet is fine — it must be REJECTED, not forwarded).
grep -o 'fp=[0-9a-f]*' /tmp/server.log | cut -d= -f2 | sort > /tmp/got_fp.txt
if [ -s /tmp/got_fp.txt ] && while read -r fp; do grep -qx "$fp" /tmp/got_fp.txt || exit 1; done < /tmp/expect_fp.txt; then
  echo "fingerprints  : MATCH (5/5 valid)"
else
  echo "fingerprints  : MISMATCH"; pass=0
fi

# ip -s link RX line order: bytes packets errors dropped missed mcast
rx_nums=$(grep -A1 'RX:' /tmp/tunstat.txt | tail -1)
rx_bytes=$(echo "$rx_nums" | awk '{print $1}')
rx_pkts=$(echo "$rx_nums" | awk '{print $2}')
echo "kernel TUN RX : $rx_pkts packets / $rx_bytes bytes (expect 5 / 4676)"
[ "$rx_pkts" = "5" ] || pass=0
[ "$rx_bytes" = "4676" ] || pass=0

echo "========================================"
if [ "$pass" = "1" ]; then
  echo "RESULT: PASS — Day 10 TUN path fully verified."
  exit 0
else
  echo "RESULT: FAIL — see lines above."
  exit 1
fi
