# BondNet Architecture

## Goal

Bond multiple physical Internet paths into one logical encrypted tunnel, so a
Windows machine can use Wi-Fi + Ethernet + 5G (etc.) as a single connection.

## Core principle

Bonding happens **below the application TCP layer** and **above the physical
transport layer**, inside BondNet's own tunnel protocol.

We never split a raw TCP connection across paths: a TCP connection is a single
identity (one source IP), and the far server would see inconsistent identities
plus asymmetric latency/loss. Instead, application IP packets enter a virtual
adapter, get encapsulated into BondNet tunnel packets (our own sequence
numbers, encryption, authentication), and are scheduled across physical paths.
The VPS reassembles them and egresses to the Internet as one machine.

## Client

```text
Wintun → BondNet Core → encrypted UDP → physical links
```

`bondnet-client` owns everything Windows-specific: Wintun adapter, interface
discovery, per-path UDP sockets, routing exceptions (tunnel traffic must never
re-enter the virtual adapter), and eventually the Windows service.

## Server

```text
UDP → BondNet Core → Linux TUN/forwarding → Internet
```

`bondnet-server` owns everything Linux-specific: the UDP listener, session
management, the tunnel interface, and NAT/forwarding to the Internet.

## Source of truth

The tunnel protocol and its state (sessions, sequence numbers, path health)
have explicit ownership: `bondnet-protocol` owns the wire format,
`bondnet-core` owns session/sequencing/reorder state. Those semantics are
designed on later days, not Day 1.

## Dependency direction

```text
bondnet-client ─────┐
                    ↓
bondnet-core ───────┼──→ bondnet-protocol
                    │
                    ├──→ bondnet-crypto
                    │
                    └──→ bondnet-scheduler

bondnet-server ─────┘
```

Rules:

- `core` is platform-independent; it never depends on `client` or `server`.
- `protocol`, `crypto`, and `scheduler` are leaves: they know nothing about
  sockets, platforms, or each other.
- No circular dependencies. Any change to this graph needs an explicit
  proposal with trade-offs before it happens.

## BondNet Protocol v1

Implemented in `bondnet-protocol`. Currently **Version 1**. Encryption and
authentication are intentionally NOT part of this layer yet (Day 3).

### Header

Fixed **36 bytes**, all integers big-endian (network byte order):

```text
Field          | Size    | Encoding
---------------+---------+----------
Magic          | 2 bytes | ASCII "BN" (0x42 0x4E)
Version        | 1 byte  | must be 1
Flags          | 1 byte  | must be 0x00 (no flags defined in v1)
Header Length  | 2 bytes | must be 36
Session ID     | 8 bytes | u64, opaque tunnel session identifier
Sequence       | 8 bytes | u64, BondNet tunnel sequence (NOT TCP seq)
Path ID        | 2 bytes | u16, opaque physical-path identifier
Packet Type    | 1 byte  | see table below
Reserved       | 1 byte  | must be 0x00
Timestamp      | 8 bytes | u64, milliseconds since Unix epoch (caller-supplied)
Payload Length | 2 bytes | u16, exact payload byte count
```

Followed by `Payload Length` bytes of payload.

### Packet types (stable wire values)

```text
Data          = 1
Ack           = 2
PathHello     = 3
PathKeepalive = 4
PathStats     = 5
Close         = 6
```

### Validation rules (strict, no silent acceptance)

- Fewer than 36 bytes → rejected (`PacketTooShort`); never panics.
- Wrong magic, version ≠ 1, header length ≠ 36, non-zero flags, non-zero
  reserved byte, or unknown packet type → rejected.
- Total length must equal exactly 36 + declared payload length: truncated
  packets, lying length fields, and trailing bytes are all rejected.

### Payload length semantics

The `u16` field caps payloads at 65535 bytes (`MAX_PAYLOAD_LEN`). This is a
protocol-format limit, not the network/tunnel MTU — real MTU/MSS design
happens later with Wintun and VPS forwarding.

## Crypto (Day 3)

Implemented in `bondnet-crypto`. Provides the authenticated-encryption
primitive the tunnel will use; it performs no key exchange, handshake, or
session establishment.

```text
plaintext payload
        ↓
XChaCha20-Poly1305
        ↓
ciphertext + authentication tag
```

- **Confidentiality:** XChaCha20 stream cipher encrypts the payload.
- **Integrity + authentication:** the Poly1305 tag covers the ciphertext AND
  the associated data; any modification is detected on decrypt.
- **AAD:** associated data is authenticated but not encrypted. The future
  design passes the serialized Day 2 packet header as AAD, so the header
  stays visible for routing/validation while the payload stays secret.
- **Key:** 256-bit (`CryptoKey`, 32 bytes). Key bytes are zeroized on drop
  as best-effort memory hygiene.
- **Nonce:** 24-byte XChaCha nonce, explicitly caller-supplied — the crate
  never generates nonces itself, so the future session layer keeps
  deterministic, auditable control over nonce assignment.
- **Nonce uniqueness:** a (key, nonce) pair must never repeat. Reusing a
  nonce with the same key destroys both confidentiality and authenticity
  guarantees; the session layer (not this primitive) owns nonce lifecycle.

Cryptographic primitives are delegated to the maintained RustCrypto
`chacha20poly1305` crate (currently 0.11) — BondNet implements no cipher,
MAC, or AEAD construction by hand, and decrypting attacker-controlled bytes
never panics.

> The Day 3 crypto module does not perform key exchange or session
> establishment. It provides the authenticated-encryption primitive that
> later BondNet session code will use.

## Scheduler (Day 4)

Implemented in `bondnet-scheduler`. Answers one question: *which physical
path should carry the next tunnel packet?* It is a pure decision library —
no sockets, no platforms, no packet bytes — so both `bondnet-client` and
`bondnet-core` can use it without platform coupling. Zero external
dependencies.

```text
Physical paths
      ↓
Path statistics (caller-supplied)
      ↓
Path scoring (PathScorer: replaceable policy)
      ↓
Weighted deterministic selection (smooth weighted round-robin)
      ↓
PathId
```

- **Path model:** `PathId(u16)` matches the protocol's `path_id` width.
  `PathState` bundles id, `PathHealth`, and `PathStats`.
- **Statistics:** bandwidth (`u64` bps, no assumed ceiling), RTT (`u32` ms;
  zero means "unknown", never a divide-by-zero), loss in integer
  parts-per-million (`1% = 10_000 ppm`), jitter (`u32` ms), in-flight bytes,
  and a congestion target (`capacity_bytes`; zero disables the penalty).
- **Health contract:** `Healthy` → eligible, `Degraded` → eligible but
  penalized (quarter weight in the MVP scorer), `Unhealthy` → never
  selected. Exclusion is enforced by the scheduler itself, never trusted
  to the scorer.
- **Scoring:** isolated behind the `PathScorer` trait. The MVP
  `DefaultScorer` multiplies per-mille factors
  (`bandwidth × health × latency × loss × jitter × congestion`) in `u128`
  with saturating arithmetic — no overflow on `u64::MAX` input, no NaN,
  no float. The formula is deliberately easy to replace.
- **Selection:** smooth weighted round-robin over explicit per-path cursors.
  Higher weight → proportionally more selections, spread smoothly through
  time; lower weight → fewer but non-zero selections. Fully deterministic:
  no RNG, `BTreeMap` ordering for tie-breaking, same updates always give
  the same sequence.
- **API:** `update_path` (upsert + immediate re-weight), `remove_path`,
  `select_path() -> Option<PathId>` (`None` when nothing is eligible).

> The Day 4 scheduler performs no real network measurement. It consumes
> caller-supplied statistics; real measurement arrives later from the
> path-health subsystem (measured throughput, RTT, loss, jitter, queue
> depth, path failures/recovery), and the scoring policy is built to be
> swapped when it does.

## Reordering (Day 5)

Implemented in `bondnet-core::reorder`. Answers one question: *in what order
do tunnel packets leave the tunnel?* It is a deterministic, dependency-free
data structure — no sockets, no timers, no encryption, no path logic — so it
never depends on `bondnet-protocol::Packet` and operates purely on
`(sequence, value)` pairs.

```text
Path A ── seq 10 ────────┐
Path B ── seq 12 ──┐     │
Path A ── seq 11 ──┼─────┤
                   ▼     ▼
              Reorder Buffer
                   │
              10 → 11 → 12
```

- **BondNet's own tunnel sequence:** the `u64` tunnel sequence from the
  protocol header is BondNet's, not TCP's. Packets can arrive out of order
  because different physical paths have different RTT and loss. The buffer
  holds "future" packets and releases them only when every earlier sequence
  has arrived. TCP behavior is never touched.
- **Data structure:** a `BTreeMap<u64, T>` keyed by sequence. Ordered keys
  give deterministic behavior and trivial gap inspection. No premature
  ring-buffer optimization; that waits for benchmarks on real traffic.
- **Delivery:** pushing the expected sequence releases it plus every
  buffered packet that is now contiguous, in ascending order. Missing
  sequences are **never auto-skipped** — if 12 and 13 are buffered while 11
  is missing, they stay buffered. Skipping is a reliability/policy decision
  for a later layer; auto-skipping would silently lose tunnel packets.
- **Duplicates:** a duplicate of an already-delivered sequence is behind the
  delivery frontier and is rejected as `TooOld` — never delivered twice. A
  duplicate of a buffered sequence never overwrites the original; the first
  value wins and the duplicate is returned to the caller.
- **Late packets:** any sequence below `next_expected` is rejected as
  `TooOld` and never moves the frontier backwards.
- **Bounded memory:** capacity (`max_buffered`) is configured up front. A
  full buffer rejects new out-of-order packets with `BufferFull` instead of
  growing; nothing here can panic on any input, and all arithmetic is
  overflow-checked.
- **Gap reporting:** `gap()` exposes `{ expected, first_buffered, distance,
  buffered }` for a future timeout/recovery layer, which will decide when a
  missing sequence has been gone too long. Day 5 only *reports* gaps.
- **u64 boundary:** no wrap-around semantics are implemented. Delivering
  `u64::MAX` permanently exhausts the buffer; afterwards pushes are
  `Duplicate` (for `u64::MAX`) or `TooOld`. This is explicit, not silent.

> Day 5 implements no UDP, no Wintun, no retransmission, no ACK handling,
> no timeout policy, no VPS networking, and no real bonding. It is the
> ordering primitive the tunnel session will later sit on.

## VPS UDP server (Day 6)

Implemented in `bondnet-server`. Answers one question: *can a real UDP
datagram carrying a valid BondNet packet reach the VPS, be decoded by our
existing protocol implementation, and be identified by session ID + path
ID — without crashing on malformed traffic?*

- **Receive loop:** Tokio UDP socket (features: `net`, `rt`,
  `rt-multi-thread`, `macros`, `signal`, `sync`, `time` — nothing else).
  Bind → log local address → receive into a fixed 65571-byte buffer
  (`HEADER_LEN + MAX_PAYLOAD_LEN`, sized from protocol constants, never
  duplicated magic numbers). The buffer is larger than any possible UDP
  datagram, so the runtime can never silently truncate into it; anything
  that is not a valid packet is rejected by `Packet::decode`, never by
  unsafe truncation.
- **Validation:** every datagram goes through
  `bondnet_protocol::Packet::decode`. The server duplicates zero parsing
  logic. Decode failure → `malformed_packets += 1`, one concise WARN line
  (`remote`, length, error), continue. Malformed input never panics, never
  stops the loop.
- **Session/path registry:** in-memory `HashMap<u64, SessionState>`, each
  session holding `HashMap<u16, PathState>`. Per `(session_id, path_id)`:
  latest `remote_addr`, `last_seen`, `packets_received`, `bytes_received`,
  `last_sequence`. Observation only — no authentication, no session
  lifecycle, and UDP being connectionless, the stored address is just the
  latest observed source. Sequences are observed, never reordered, never
  rejected for being out of order; timestamps are decoded and ignored.
- **Telemetry:** server counters `datagrams_received`, `valid_packets`,
  `malformed_packets`, `bytes_received` as atomics, readable without
  stopping the loop. Per-packet `RX session=… path=… seq=… type=… payload=…
  remote=…` lines only with `--verbose`; payload contents and keys are
  never logged.
- **No fake ACKs:** `PacketType::Ack` is recognized and counted like any
  other type, but the server never generates an ACK — the ACK payload
  contract does not exist yet, and inventing one would be fake protocol.
- **Shutdown:** Ctrl+C via Tokio signals → `shutdown requested` →
  `server stopped`, no panic.
- **Config:** `ServerConfig { bind_addr, verbose }`, default
  `0.0.0.0:51820`, parsed from a minimal hand-rolled `--bind`/`--verbose`
  CLI (no clap for one argument).

> Day 6 explicitly does NOT implement: encryption, key exchange, Wintun,
> TUN, NAT, Internet forwarding, routing, bonding, reordering,
> retransmission, scheduler integration, ACK generation, or any
> persistent store. It is plaintext by design — a development networking
> component, not a production VPN server.

### Future routing-recursion trap (do not build yet)

When the Windows client eventually sends tunnel UDP traffic, that
traffic MUST go out a **physical interface** directly to the VPS:

```text
BondNet tunnel UDP → physical interface → Internet → VPS   (correct)
```

and never:

```text
BondNet tunnel UDP → Wintun → BondNet tunnel UDP → …       (infinite recursion)
```

The tunnel's own transport packets must bypass the virtual adapter they
carry everyone else's traffic through. Day 7 (physical-path selection)
owns this problem.

## First physical-path UDP transport (Day 7)

Implemented in `bondnet-client`. Answers one question: *can BondNet bind
a UDP socket to one specific physical-interface IPv4 address and send
valid BondNet protocol packets through that physical path to the VPS?*

- **Transport:** `UdpPath::bind(UdpPathConfig)` binds the configured
  `local_addr` (e.g. `192.168.0.170:0` — an IPv4 address owned by the
  intended physical adapter; port 0 allocates an ephemeral port), then
  `connect`s the VPS endpoint. The CLI prints configured vs. actual
  bound address so the operator can verify the socket really owns the
  physical address before any packet is sent.
- **Binding is not routing (stated accurately):** `bind()` pins the
  socket's local address; the OS routing table still decides the egress
  interface. For a local address owned by exactly one adapter, that
  adapter is the one the OS uses. Selecting a local IP is
  address-based path selection — related to, but not identical with,
  selecting an interface by name. No `SO_BINDTODEVICE`, no `ip rule`,
  no interface-name fields that are never used.
- **Connected UDP:** `bind(local)` → `connect(remote)` → `send(packet)`.
  This does NOT make UDP TCP-like; it only fixes the default peer so
  `send`/`recv` need no per-datagram address, and the OS drops datagrams
  from any other source.
- **Packet stamping:** `next_packet()` stamps the configured `session_id`
  (explicit, no negotiation yet) and `path_id` (logical BondNet ID from
  configuration — never derived from port, interface index, or IP), a
  monotonic tunnel sequence from an `AtomicU64` starting at the
  configured `initial_sequence` (no wrap handling yet), and the current
  Unix time in milliseconds (the protocol transports it; the client owns
  the clock). Payloads are existing packet types only (`PathHello`,
  `Data`, `PathKeepalive`) — no invented payload schemas, no ACK
  generation.
- **Receive:** `recv_packet()` decodes one datagram from the connected
  peer. Malformed input yields `DecodeFailed` and leaves the transport
  usable; the error is per-datagram, never fatal.
- **Telemetry:** per-path `packets_sent`, `bytes_sent`,
  `packets_received`, `bytes_received`, `last_sequence_sent`. No
  scheduler integration — the scheduler waits for multiple paths and
  real measurements.
- **Errors:** `TransportError` with chained sources (`BindFailed`,
  `ConnectFailed`, `SendFailed`, `ReceiveFailed`, `EncodeFailed`,
  `DecodeFailed`, `InvalidLocalAddress`, `ClockUnavailable`). No
  `unwrap`/`expect`/`panic!` in networking paths.
- **CLI/library split:** the binary is a thin wrapper — parse args,
  `UdpPath::bind`, send a finite burst (`PathHello`, `Data…`,
  `PathKeepalive`), print per-packet lines, exit. Not a daemon.

### Routing-recursion invariant (future, documented not solved)

Tunnel transport packets must bypass the BondNet virtual adapter and use
their selected physical path:

```text
Physical Wi-Fi → BondNet UDP transport → VPS        (correct)
BondNet UDP transport → Wintun → …                  (infinite recursion, forbidden)
```

Day 7 has no Wintun, so there is no recursion today; Day 8+ must preserve
this invariant when the virtual adapter arrives.

> Day 7 explicitly does NOT implement: Wintun, virtual adapter, TUN,
> packet interception, Internet forwarding, NAT, a second physical path,
> bonding, encryption integration, retransmission, reorder integration,
> congestion control, adaptive scheduling, authentication, GUI, Windows
> service, database, TCP, or QUIC. One path, plaintext, dev-only.

## Wintun virtual adapter (Day 8)

Implemented in `bondnet-client` (`src/wintun/`). Answers one question:
*can BondNet load the Wintun driver, own a virtual Layer-3 adapter, and
move raw IP packets across the Wintun data plane in safe Rust?*

- **Layer-3 semantics:** Wintun exposes IPv4/IPv6 packets, never Ethernet
  frames. Day 8 treats them as opaque bytes — no Ethernet headers, no
  fake MACs, no IP parsing, no modification.
- **DLL loading:** `WintunLibrary::load()` resolves `<exe-dir>\wintun.dll`
  via `GetModuleFileNameW` and loads it with `LoadLibraryExW` on the
  absolute path (`LOAD_WITH_ALTERED_SEARCH_PATH`). No current-directory
  search, no download, no silent install, no binary DLL in the source
  tree. All 11 required symbols (`WintunCreateAdapter` …
  `WintunGetRunningDriverVersion`) are resolved at startup; one missing
  symbol fails initialization with `SymbolMissing(name)` and unloads the
  DLL. `WintunSetLogger` is deliberately optional and not required.
- **Adapter lifecycle:** `WintunAdapter::open_or_create("BondNet")`
  opens the existing adapter, and creates it only when `WintunOpenAdapter`
  fails with `ERROR_FILE_NOT_FOUND` (2) or `ERROR_NOT_FOUND` (1168, seen
  on Windows 11 for a missing adapter). Any other failure (access denied,
  driver failure) propagates unchanged — never misread as "missing".
  Creation needs Administrator privileges. The adapter holds an
  `Arc<WintunLibrary>`, so the DLL cannot unload while in use.
- **Session:** `WintunSession::start(&adapter, capacity)` borrows the
  adapter, so a session can never outlive it — close-while-alive is
  unrepresentable. Capacity is validated in Rust before FFI: 128 KiB –
  64 MiB, power of two, default 4 MiB (`0x400000`). `Drop` ends the
  session, then the adapter closes.
- **Receive:** `recv_packet()` returns `Ok(Some(Vec<u8>))` (bytes copied
  into owned memory BEFORE `WintunReleaseReceivePacket`), `Ok(None)` on
  `ERROR_NO_MORE_ITEMS`. The raw Wintun pointer never leaves the module,
  is never stored, and is released exactly once. `wait_for_packet(timeout)`
  sleeps on `WintunGetReadWaitEvent` — no busy-loop.
- **Send:** `send_packet(&[u8])` validates `1..=65535` bytes, allocates
  via `WintunAllocateSendPacket`, copies, then `WintunSendPacket`
  (ownership transfers to Wintun; never freed manually). A full send
  ring is `SendBufferFull`, never a panic, never a leaked allocation.
- **Errors:** `WintunError` carries raw `GetLastError()` codes, rendered
  through `FormatMessageW` on Windows (`"failed to create Wintun adapter:
  Windows error 5 (Access is denied)"`).
- **Smoke test:** `bondnet-client wintun-smoke [--adapter NAME]
  [--send-test]` (Windows only) loads the DLL, prints the driver version,
  opens/creates the adapter, starts a session, optionally sends one
  synthetic IPv4/UDP packet at TEST-NET-1 (proves the send path; Wintun
  does NOT loop back), then counts received packets until Ctrl+C and
  shuts down cleanly. No payload logging.
- **Platform honesty:** on non-Windows targets the types compile but
  `WintunLibrary::load()` fails with `DllNotFound` — Linux CI stays
  green without pretending the data plane works there.

### Explicit non-goals (Day 8 configures nothing)

Day 8 creates the adapter and NOTHING else: no virtual IP, no routes,
no default-route change, no DNS, no MTU, no gateway, no NAT, no VPS
forwarding, no bonding, no second path, no crypto integration. The
adapter can exist without BondNet being a functioning VPN.

> Day 8 does not provide Internet access through BondNet yet.

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

### Design decisions

- **No new protocol.** The existing `PacketType::Data` envelope carries the
  Wintun bytes unchanged. No IP length, TCP metadata, ifIndex or any other
  application envelope inside the payload — the BondNet header already
  carries session/path/sequence.
- **No second UDP implementation.** `DataPlane` owns no socket; it calls
  `UdpPath::send_new`. Sequence numbers stay the Day 7 tunnel sequence.
- **Async/blocking boundary (brief Option A).** The Wintun reader runs on a
  dedicated OS thread inside `std::thread::scope` (so the session can borrow
  the adapter), entered via `tokio::task::block_in_place` — the blocking
  `wait_for_packet` never runs on a Tokio executor thread. The reader pushes
  into a bounded `tokio::sync::mpsc` channel
  (`DATA_PLANE_CHANNEL_CAPACITY` = 1024 packets ≈ 1.5 MiB worst case) with
  `try_send`: a full channel drops the newest packet and counts
  `backpressure_dropped` — never blocks the reader, never grows memory.
- **Routing-recursion guard.** The tunnel socket binds the explicit physical
  local IPv4 (e.g. `192.168.0.170:0`); Wintun is only the inner-packet
  source, never the tunnel egress. No routes/DNS/MTU/NAT are touched.
- **MTU honesty.** Budget is 1500-byte inner packets (1536-byte datagrams),
  which may exceed a 1500-byte path MTU and rely on IP fragmentation. Real
  MTU/MSS handling is a Day 10+ task; oversized packets are rejected and
  counted, never fragmented by BondNet.
- **Plaintext.** Payloads are still unencrypted (Day 3 crypto integration is
  a later milestone). The server logs a test-only FNV-1a fingerprint per
  Data packet (`fp=`) — NOT cryptographic, NOT authentication — so the smoke
  test confirms byte-exact delivery without dumping packet bytes.
- **Shutdown.** Ctrl+C sets an `AtomicBool`; the reader wakes from 100 ms
  wait slices, the session drops inside the scope (before the adapter),
  the channel closes, the sender drains, and the process exits. No
  deadlocks: the reader never blocks on a full channel.

### CLI

```text
bondnet-client tunnel-smoke --local 192.168.0.170:0 --remote VPS:51820 \
  --path-id 1 --session-id 1001 [--adapter BondNet] [--verbose]
```

`--synthetic` skips Wintun (portable; also runs on Linux) and sends
deterministic synthetic IPv4/UDP packets of 64/512/1200/1400/1500 bytes
through the same `DataPlane` code path — it proves protocol + transport +
server before the real adapter is involved.

### Explicit non-goals (Day 9 forwards nothing)

The VPS decodes and counts `Data` packets; it does NOT forward them to the
Internet, has no TUN device, no NAT, no iptables rules. No second path, no
bonding, no scheduler, no retransmission, no ACK protocol, no encryption
integration, no GUI/service, no Windows route changes.

> Day 9 does not provide Internet access through BondNet. The correct claim
> is: BondNet transports Wintun Layer-3 packets over a real UDP tunnel to
> the VPS, which recovers the exact payload bytes.

## Day 10 — VPS TUN + Internet forwarding (upload direction)

Day 10 turns the VPS into the first Internet-facing endpoint, upload
direction only:

```text
BondNet DATA payload (one raw IP packet)
        │
        ▼
validate_ip_packet() — structural IPv4/IPv6 check, never panics
        │  reject: IP_REJECT log + tun_invalid_ip counter
        ▼
bounded mpsc queue (TUN_QUEUE_CAPACITY = 1024)
        │  full: drop newest + tun_queue_dropped (flat memory, explicit)
        ▼
dedicated writer thread ("bondnet-tun-writer")
        │  NOT a Tokio executor thread — blocking write(2) is safe here
        ▼
TunDevice::write_packet() — one write(2) per packet
        │  IFF_TUN | IFF_NO_PI (Layer-3, no Ethernet, no packet-info header)
        │  O_NONBLOCK fd: WouldBlock → drop + tun_write_errors, never hang
        │  NOT persistent: kernel destroys the device when the fd closes
        ▼
Linux kernel routing → NAT/masquerade → Internet
```

### Forwarding gate

Only packets passing ALL of these reach the TUN device:

1. UDP datagram decodes via `bondnet-protocol` (`Packet::decode`)
2. `PacketType::Data` (any other type returns before validation)
3. `validate_ip_packet()`: exactly one well-formed IPv4/IPv6 packet —
   version nibble, IHL ≥ 5, header bounds, declared length == buffer
   length (trailing bytes rejected, not trimmed)
4. Queue `try_send` succeeds

Arbitrary UDP datagrams can never become TUN traffic.

### Design decisions

- **TUN is opt-in.** Without `--tun-name` the server is byte-for-byte Day
  9 behavior (decode/count/log). `--tun-addr`/`--tun-prefix` are required
  with `--tun-name`; `--tun-addr`/`--tun-prefix` without `--tun-name`
  are rejected instead of silently ignored.
- **The server creates the device, the admin configures the network.**
  Address assignment (`ip addr add`), link up, `ip_forward`, NAT rules,
  and FORWARD-chain rules are explicit administrator commands —
  documented in `docs/vps-day10-setup.md` and printed with the user's
  exact values by `bondnet-server --print-setup`. The server never runs
  shell commands, never flushes firewalls, never changes the default
  route, and never disables `rp_filter` globally (scoped `=2` on the TUN
  device only, and only if return traffic needs it — documented).
- **Startup is read-only about the host.** With TUN enabled the server
  WARNS (never fails, never fixes) if `/proc/sys/net/ipv4/ip_forward`
  is `0` or `--wan-iface` is missing from `/sys/class/net/`.
- **Privileges fail loudly.** Without `CAP_NET_ADMIN`,
  `TunDevice::create` returns `PermissionDenied` naming the missing
  capability. No fake-device fallback.
- **Read path exists, unwired.** `TunDevice::read_packet()` is
  implemented for the Day 11 return path but nothing calls it yet;
  `tun_packets_read`/`tun_bytes_read` stay 0.
- **Shutdown.** Ctrl+C → UDP loop breaks → queue sender dropped →
  writer drains pending packets → thread joined → device fd closed →
  kernel destroys the interface. No stale `bondtun0`.
- **Still plaintext.** No encryption/auth yet (later milestone).

### CLI

```text
bondnet-server --bind 0.0.0.0:51820 --verbose \
  --tun-name bondtun0 --tun-addr 10.200.0.1 --tun-prefix 24 \
  [--wan-iface eth0] [--print-setup]
```

### Explicit non-goals (Day 10 is upload-only)

No Windows return/download path, no second physical path, no bonding,
no adaptive scheduler, no encryption integration, no key exchange, no
retransmission/ACK/congestion-control/replay-protection, no GUI/service,
no automatic network configuration, no DNS interception, no MTU
auto-discovery.

> Day 10 proves BondNet DATA → VPS TUN → kernel routing → NAT →
> Internet (upload). The download path (Internet → TUN → BondNet →
> Windows) is Day 11.

## Day 11 — Return/download path (TUN → BondNet → Windows)

Day 11 completes the bidirectional tunnel: packets the kernel routes
into `bondtun0` (Internet responses, after NAT) travel back over UDP and
are written into the Windows Wintun adapter.

```text
Internet response / routed IP packet
       ↓
  Linux kernel
       ↓
   bondtun0
       ↓
 BondNet VPS server (TUN reader thread → return queue → sender task)
       ↓
 BondNet DATA encapsulation (UDP)
       ↓
 Windows BondNet client (UDP receiver → validate → Wintun thread)
       ↓
   Wintun send ring
       ↓
 Windows IP stack
```

### Direction by arrival interface (no new header field)

Both directions use `PacketType::Data`. Direction is operational, never
a header flag:

- **Server:** UDP→TUN is upload (Day 10 writer thread); TUN→UDP is
  return (Day 11 reader thread). The reader never feeds the writer queue.
- **Client:** Wintun→UDP is upload (Day 9); UDP→Wintun is return
  (Day 11). The return processor never feeds the upload `DataPlane`.

The two pipelines share the TUN fd (server) but never each other's
queues, so packets cannot loop inside BondNet.

### Return sequence numbers are directional

The client stamps upload packets from its `UdpPath` counter; the server
stamps return packets from a per-`(session, path)` `return_sequence`
counter (starts at 1). The two counters live in different directional
spaces — a receiver must never compare an upload sequence with a return
sequence. No reorder buffer consumes return packets yet; when one does,
it must key by direction.

### Endpoint association (explicit, observed, expiring)

The server is told which `(session_id, path_id)` owns the TUN return
traffic via `--tun-return-session` / `--tun-return-path` (requires
`--tun-name`). The destination address is the *observed* source of that
pair (Day 6 registry), rejected when unknown or older than
`--tun-return-max-age-secs` (default 300). Malformed datagrams never
create or overwrite the association — only decoded packets do.

**Trust limitation (documented, not solved):** the association is still
unauthenticated observation. A spoofed source address redirects return
traffic. Session authentication is a later milestone; do not deploy this
as a production VPN.

### Client return validation

`ReturnProcessor` (in `bondnet-client`) requires, in order: successful
`Packet::decode`, `PacketType::Data`, matching session ID, matching path
ID, then `validate_ip_packet` (the same structural gate as the server,
now in `bondnet-protocol::ip`). Only the exact payload bytes reach
Wintun, via the `WintunWriter` trait (fake in tests, real
`WintunSession::send_packet` on Windows).

### Telemetry (return path)

Server: `tun_packets_read`, `tun_bytes_read`, `tun_read_errors`,
`return_packets_sent`, `return_bytes_sent`, `return_invalid_ip`,
`return_no_endpoint`, `return_send_errors`, `return_backpressure_dropped`.
Client: `packets_received`, `bytes_received`, `wintun_packets_written`,
`wintun_bytes_written`, `invalid_protocol`, `invalid_session_path`,
`invalid_ip`, `wintun_write_errors`, `backpressure_dropped`.

### CLI

```text
bondnet-server --tun-name bondtun0 --tun-addr 10.200.0.1 --tun-prefix 24 \
  --tun-return-session 1001 --tun-return-path 1 \
  [--tun-return-max-age-secs 300]

bondnet-client tunnel-smoke --local ADDR:PORT --remote ADDR:PORT \
  --path-id 1 --session-id 1001 --return [--synthetic] [--verbose]
```

### Explicit non-goals (Day 11 is the return data path)

No second physical path, no multipath bonding, no adaptive scheduling,
no encryption/key-exchange integration, no ACKs/retransmission, no
production replay protection, no Windows route/DNS changes, no full
production VPN service, no automatic network configuration.

> Day 11 proves the return data path exists and is correct. It does not
> prove end-to-end Internet connectivity — that needs a real VPS with NAT
> and a real client, which is Day 12.

## Day 13 — Second physical path preparation

Day 13 introduces the configuration and transport abstractions for two
independent physical UDP paths. No scheduling, bonding, failover, or
encryption is added — this is preparation only.

### Configuration: `PhysicalPathConfig`

Each path has a name (for logs), a stable `path_id`, a local bind
address, a VPS remote address, and an enabled flag. Session identity
stays separate: the session ID is attached when the path is built into
a `UdpPath`, so two paths share a session but never a path ID.

Validation (`validate_path_configs`) rejects duplicate path IDs even
when local addresses differ, enabled paths with a zero remote port,
non-IPv4 addresses, and empty names. Disabled paths are validated but
never bound.

### Transport: `PathManager`

The manager holds the configured paths and binds each enabled one to
its own `UdpPath` (own UDP socket, own metrics, own error state).
Initialization is per-path: a failure is recorded on that path and the
others continue. `shutdown_path(id)` drops one path's transport without
touching the others; `shutdown_all()` is idempotent.

The manager does not schedule traffic or feed the data plane — Day 13
is about independently creating and observing paths.

### Server: no changes needed

The server's registry is keyed by `(session_id, path_id)` with per-path
`remote_addr`, counters, and return sequence. Two path IDs from different
source addresses are already tracked independently; a packet for one
path never overwrites another's association. Verified by regression
tests, not a rewrite.

### Diagnostics: `path-diag`

```text
bondnet-client path-diag --session-id 1001 \
  --path1-id 1 --path1-local 192.168.1.10:0 --path1-remote VPS:51820 \
  --path2-id 2 --path2-local 192.168.2.10:0 --path2-remote VPS:51820 \
  [--path1-name NAME] [--path2-name NAME] [--path2-disabled] [--verbose]
```

Reports each path's ID, actual bound local address (ephemeral port
resolved), and remote endpoint; sends one `PathHello` per initialized
path (the existing control type — the server records it via normal
observation); shuts both down cleanly. Proves the client can create two
independent transports; server receipt is verified separately via its
verbose log. A second socket on another local IP is NOT proof of two
independent Internet connections.

### Explicit non-goals (Day 13 prepares only)

No multipath scheduling, no packet distribution across paths, no
reorder buffer changes, no bonding, no failover, no encryption, no
ACKs/retransmission, no replay protection, no route/DNS changes, no
MTU discovery, no production authentication.

> Day 13 proves two paths can be configured, bound, observed, and shut
> down independently. Using both for traffic is Day 14.
