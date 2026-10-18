# BondNet Day 10 — VPS setup: TUN + forwarding + NAT

This document is for the administrator of the Linux VPS. Every command
below is meant to be run **by a human with sudo** — `bondnet-server`
never executes any of them itself and never rewrites host networking on
its own.

Assumptions used in the examples (replace with your values):

| Item          | Example         | From                               |
| ------------- | --------------- | ---------------------------------- |
| TUN device    | `bondtun0`      | `--tun-name`                       |
| TUN address   | `10.200.0.1/24` | `--tun-addr` / `--tun-prefix`      |
| TUN subnet    | `10.200.0.0/24` | derived (see "Choosing a subnet")  |
| WAN interface | `eth0`          | **discovered**, never assumed (§3) |

Generate the exact commands for your configuration at any time:

```bash
bondnet-server --tun-name bondtun0 --tun-addr 10.200.0.1 --tun-prefix 24 \
  --wan-iface eth0 --print-setup
```
