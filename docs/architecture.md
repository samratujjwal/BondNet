## Day 9 — Wintun → BondNet Data → UDP path → VPS (first data plane)

Day 9 wires Days 6/7/8 together into the first real tunnel data path:

```text
Wintun ring (real Layer-3 packet, Vec<u8>)
        │
        ▼
DataPlane::send_wintun_packet(&[u8])
        │  validate: non-empty, ≤ MAX_WINTUN_PACKET_LEN (1500)
        │  wrap: PacketType::Data, payload = exact Wintun bytes
        ▼
UdpPath::send_new (Day 7: session/path/monotonic tunnel sequence)
        │  UDP datagram on the PHYSICAL interface binding
        ▼
Internet
        ▼
bondnet-server: decode → Data counters → DATA_RX log line
```
