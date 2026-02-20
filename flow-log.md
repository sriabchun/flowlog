# NFT Flow Log — eBPF/XDP Flow Collector Daemon

## 1. Overview

Build a lightweight daemon (`nft-flow-log`) that attaches an XDP program to a TAP
interface of a virtual machine, aggregates network flow data in kernel-space using
eBPF maps, and periodically exports it via IPFIX (RFC 7011) over UDP to an
external collector (pmacct).

The feature set must be comparable to
[AWS VPC Flow Logs v5](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html).

**Principles: KISS.** Simple, flat code. No frameworks. No speculation.
If something is unclear — stop and ask.

---

## 2. Scope

| In scope | Out of scope |
|---|---|
| Single TAP interface per daemon instance | Multi-TAP multiplexing |
| IPv4 + IPv6 dual-stack | Tunneled/encapsulated traffic (GRE, VXLAN) |
| TCP, UDP, ICMP, SCTP identification | Deep packet inspection / L7 |
| Kernel-side flow aggregation (eBPF maps) | Userspace aggregation |
| Bidirectional biflow (RFC 5103) with configurable direction filter | |
| IPFIX export over UDP | IPFIX over TCP/SCTP |
| ACCEPT/REJECT action via conntrack/nftables | Full firewall rule matching |
| Optional 1:N packet sampling | |
| Active timeout export (configurable, default 60s) | Idle/TCP-state-driven export |

---

## 3. Architecture

```
┌──────────────────────────────────────────────────────────┐
│  VM                                                      │
│   eth0 ──► tap0 (host side)                              │
└──────────────────────────────────────────────────────────┘
       │
       │  packets in both directions traverse TAP
       ▼
┌──────────────────────────────────────────────────────────┐
│  XDP program (nft_flow_xdp.bpf.c)                        │
│  • Parse L2/L3/L4 headers                                │
│  • Determine direction: ingress (host→VM) / egress (VM→host)  │
│  • Apply direction filter (both/ingress/egress)          │
│  • Normalize flow key: initiator = lower IP:port         │
│  • Update initiator or responder counters in biflow entry│
│  • Optional sampling: skip N-1 out of N packets          │
│  • Return XDP_PASS (never drops traffic)                 │
└──────────────────────────────────────────────────────────┘
       │
       │  BPF map (LRU hash, 64K entries, biflow values)
       ▼
┌──────────────────────────────────────────────────────────┐
│  Userspace daemon (nft_flow_log.c)                       │
│  • Loads XDP program via libbpf CO-RE                    │
│  • Every <active_timeout> seconds:                       │
│    – Iterates flow map, reads & deletes expired entries  │
│    – Encodes biflows into IPFIX messages (RFC 5103)      │
│    – Sends UDP datagrams to collector                    │
│  • Sends IPFIX Template Set on startup + periodically    │
│  • Determines ACCEPT/REJECT per flow                    │
│  • Signal handling: SIGTERM/SIGINT → graceful shutdown   │
│    (flush remaining flows, detach XDP, exit)             │
└──────────────────────────────────────────────────────────┘
       │
       │  UDP
       ▼
┌──────────────────────────────────────────────────────────┐
│  External IPFIX collector (pmacct)                       │
└──────────────────────────────────────────────────────────┘
```

---

## 4. Technology Stack

| Component | Choice | Rationale |
|---|---|---|
| Language | C | Best libbpf/XDP ecosystem, zero overhead |
| eBPF loader | libbpf (CO-RE) | Portable, no runtime deps on BCC/LLVM |
| Kernel | Linux ≥ 6.1 LTS | BTF support, LRU hash maps, XDP on TAPs |
| BPF map | `BPF_MAP_TYPE_LRU_HASH` | Auto-evicts stale entries, bounded 64K |
| IPFIX transport | UDP | Simple, standard |
| Build | Makefile + clang/llvm for BPF, gcc for userspace | |
| Test collector | pmacct | Must verify interop |

---

## 5. Data Model

### 5.1 Flow Key (BPF map key — normalized biflow key)

The flow key is **normalized**: the lower IP (or lower port if IPs are equal)
is always the "initiator". This ensures forward and reverse packets hash to the
same map entry.

```c
struct flow_key {
    __u8  family;           // AF_INET or AF_INET6
    __u8  protocol;         // IPPROTO_TCP, UDP, ICMP, etc.
    __u16 init_port;        // initiator port (normalized lower)
    __u16 resp_port;        // responder port
    __u16 _pad;
    union {
        __be32 v4;
        struct in6_addr v6;
    } init_addr;            // initiator address (normalized lower)
    union {
        __be32 v4;
        struct in6_addr v6;
    } resp_addr;            // responder address
};
```

### 5.2 Flow Value (BPF map value — biflow counters)

```c
struct flow_value {
    /* Initiator (forward) direction */
    __u64 init_packets;
    __u64 init_bytes;
    /* Responder (reverse) direction */
    __u64 resp_packets;
    __u64 resp_bytes;
    /* Shared */
    __u64 first_seen_ns;    // ktime_get_ns() of first packet (either dir)
    __u64 last_seen_ns;     // ktime_get_ns() of last packet (either dir)
    __u8  init_tcp_flags;   // cumulative OR of initiator TCP flags
    __u8  resp_tcp_flags;   // cumulative OR of responder TCP flags
    __u8  _pad[6];
};
```

### 5.3 IPFIX Information Elements (exported per biflow)

Biflow encoding per RFC 5103. The template uses forward (initiator) IEs
plus reverse (responder) IEs with the Reverse Information Element
(PEN 29305, RFC 5103 §7).

**Forward (initiator) IEs:**

| AWS Flow Log Field | IPFIX IE | IE ID | Length |
|---|---|---|---|
| srcaddr | sourceIPv4Address / sourceIPv6Address | 8 / 27 | 4 / 16 |
| dstaddr | destinationIPv4Address / destinationIPv6Address | 12 / 28 | 4 / 16 |
| srcport | sourceTransportPort | 7 | 2 |
| dstport | destinationTransportPort | 11 | 2 |
| protocol | protocolIdentifier | 4 | 1 |
| packets (fwd) | packetDeltaCount | 2 | 8 |
| bytes (fwd) | octetDeltaCount | 1 | 8 |
| start | flowStartMilliseconds | 152 | 8 |
| end | flowEndMilliseconds | 153 | 8 |
| tcp-flags (fwd) | tcpControlBits | 6 | 2 |
| action | firewallEvent (IANA IE 233) | 233 | 1 |

**Reverse (responder) IEs (PEN 29305):**

| Field | IPFIX IE | IE ID | PEN | Length |
|---|---|---|---|---|
| packets (rev) | reversePacketDeltaCount | 2 | 29305 | 8 |
| bytes (rev) | reverseOctetDeltaCount | 1 | 29305 | 8 |
| tcp-flags (rev) | reverseTcpControlBits | 6 | 29305 | 2 |

**biflowDirection IE (IE 239):** included in every record.
Value 1 = initiator, 2 = reverseInitiator, 3 = perimeter.
Always set to **1** (initiator perspective).

Two templates: one for IPv4 biflows (Template ID 256),
one for IPv6 biflows (Template ID 257).

---

## 6. Functional Requirements

### FR-1: XDP Program

1. Attach to the specified TAP interface in `XDP_FLAGS_SKB_MODE`
   (TAP devices do not support native XDP; SKB mode is required).
2. Parse Ethernet → IPv4/IPv6 → TCP/UDP/ICMP headers.
   Bail out with `XDP_PASS` for anything unparseable (ARP, etc.).
3. **Determine direction**: compare packet's source MAC against the VM's MAC
   (stored in a BPF array map, set by userspace at startup).
   - If src MAC == VM MAC → **egress** (VM→network).
   - Otherwise → **ingress** (network→VM).
4. **Direction filter**: read a `__u8 direction_filter` from a BPF array map.
   Values: 0 = both (default), 1 = ingress only, 2 = egress only.
   If packet direction doesn't match the filter, skip processing (`XDP_PASS`).
5. **Normalize flow key** for biflow: compare src and dst addresses;
   the numerically lower IP becomes the initiator. If IPs are equal, compare
   ports. This ensures forward and reverse packets map to the same entry.
6. Track whether this packet is from the initiator or responder direction.
7. Lookup-or-create entry in LRU hash map.
   On create: set `first_seen_ns`, zero all counters.
   On update: increment the correct direction's `packets`, add to correct
   direction's `bytes` (L3 payload length), OR in `tcp_flags` for the
   correct direction, update `last_seen_ns`.
8. **Sampling**: read a `__u32 sample_rate` from a BPF array map (index 0).
   If `sample_rate > 1`, use a per-CPU counter; only process every Nth packet.
   If `sample_rate ≤ 1` or map is missing, process every packet (no sampling).
9. Always return `XDP_PASS`. This is a passive observer — never drop traffic.
10. All header access must use bounds-checking helpers to pass the BPF verifier.

### FR-2: Userspace Daemon

1. Load BPF object via `libbpf` skeleton (`nft_flow_xdp.skel.h`).
2. Attach XDP program to the TAP interface.
3. Set sample rate, direction filter, and VM MAC address in BPF array maps.
4. Enter main loop:
   - Sleep for `active_timeout` seconds (default 60).
   - Iterate the LRU hash map using `bpf_map_get_next_key()` +
     `bpf_map_lookup_elem()` + `bpf_map_delete_elem()`.
   - For each biflow: determine ACCEPT/REJECT (see FR-3),
     convert timestamps from `ktime_ns` to epoch milliseconds,
     encode into IPFIX Data Set with biflow IEs (RFC 5103).
   - Send IPFIX message(s) over UDP to the collector.
5. On startup and every 5 minutes: send IPFIX Template Sets
   (one for IPv4, one for IPv6).
6. Handle `SIGTERM`/`SIGINT`: flush all remaining flows, detach XDP, close
   socket, exit 0.
7. Log to stderr. Verbosity controlled by `-v` flag.

### FR-3: ACCEPT/REJECT Determination

1. For each exported flow, query the conntrack table via `libnetfilter_conntrack`
   (or netlink directly) to check if a matching entry exists.
2. If a conntrack entry exists → `ACCEPT` (firewallEvent = 2).
3. If no conntrack entry → `REJECT` (firewallEvent = 0).
4. This is a best-effort heuristic. Document its limitations.
5. If conntrack lookup fails or is unavailable, default to `ACCEPT` and log a
   warning once.

### FR-4: IPFIX Encoding (RFC 7011 + RFC 5103 Biflow)

1. Message Header: version=10, length, export time, sequence number,
   observation domain ID (configurable, default 0).
2. Template Set (Set ID = 2):
   - Template ID 256: IPv4 biflow (forward IEs + reverse IEs + biflowDirection).
   - Template ID 257: IPv6 biflow (same structure, v6 address IEs).
   - Reverse IEs use enterprise bit with PEN 29305 per RFC 5103 §7.
3. Data Set: Set ID = Template ID, followed by biflow records.
4. MTU-aware: do not exceed 1400 bytes per UDP datagram.
   If more flows, send multiple messages.
5. Sequence number: cumulative count of data records exported (per RFC 7011 §3.1).

---

## 7. CLI Interface

```
nft-flow-log -i <interface> [-c <collector_ip>:<port>] [options]

Required:
  -i <ifname>         Network interface (e.g. tap0, eth0, ens3)

Optional:
  -c <ip>:<port>      IPFIX collector address (e.g. 10.0.0.1:4739)
                      If omitted, flows are printed to stderr.
  -t <seconds>        Active timeout, default 60
  -s <rate>           Sampling rate: N (static 1:N), or auto:MIN:MAX (dynamic).
                      Dynamic mode targets 250 Kpps effective rate, adjusting
                      the sampling ratio between 1:MIN and 1:MAX each cycle.
                      Example: -s auto:1:1000
  -D <direction>      Direction filter: both (default), ingress, egress
  -N                  Use native XDP mode (requires driver support;
                      default is SKB/generic mode which works on any NIC)
  -P                  Use per-CPU flow map (eliminates lock contention on
                      multi-queue NICs; uses more memory: ~4 MB × num_cpus)
  -d <domain_id>      IPFIX Observation Domain ID, default 0
  -v                  Verbose logging to stderr
  -h                  Help
```

---

## 8. Non-Functional Requirements

| Requirement | Target |
|---|---|
| CPU overhead | < 1% per 100 Kpps on modern CPU |
| Memory | ≤ 4 MB for flow map (64K entries) + fixed userspace |
| Startup time | < 1 second (BPF load + attach) |
| No packet drops | XDP program always returns XDP_PASS |
| Graceful shutdown | Flush + detach within 2 seconds |
| No external runtime deps | Static binary, BPF CO-RE (BTF from kernel) |

---

## 9. File Structure

```
nft-flow-log/
├── Makefile
├── README.md
├── src/
│   ├── nft_flow_xdp.bpf.c        # XDP/eBPF program (kernel-side)
│   ├── nft_flow_log.c             # Userspace daemon (main)
│   ├── ipfix.c                    # IPFIX encoding + UDP send
│   ├── ipfix.h
│   ├── flow.h                     # Shared flow_key/flow_value structs
│   ├── conntrack.c                # ACCEPT/REJECT lookup
│   └── conntrack.h
└── flow-log.md                    # This specification
```

**Total: ~6 source files.** Keep it flat. No subdirectories beyond `src/`.

---

## 10. Build

```makefile
# Dependencies: clang >= 14, llvm, libbpf-dev, bpftool,
#               libnetfilter-conntrack-dev

# 1. Compile BPF: clang -O2 -target bpf -g -c nft_flow_xdp.bpf.c
#    (uses linux/ headers directly — no vmlinux.h needed)
# 2. Generate skeleton: bpftool gen skeleton nft_flow_xdp.bpf.o > nft_flow_xdp.skel.h
# 3. Compile userspace: gcc -O2 nft_flow_log.c ipfix.c conntrack.c -lbpf -lelf -lz -lnetfilter_conntrack
```

The Makefile must automate all three steps.

---

## 11. Testing

### 11.1 Unit Testing (developer workstation)

1. **BPF verifier**: `nft_flow_xdp.bpf.o` must load on kernel 6.1 without
   verifier errors. Test with `bpftool prog load`.
2. **IPFIX encoding**: Write a small test harness that creates fake flow records,
   encodes them, and validates the binary output against expected bytes.
3. **Conntrack stub**: Test the ACCEPT/REJECT logic with a mock that returns
   found/not-found.

### 11.2 Integration Testing

1. Create a veth pair or TAP + network namespace.
2. Run `nft-flow-log` on the TAP.
3. Generate traffic with `iperf3` / `ping` / `curl`.
4. Run `pmacctd` (pmacct) as collector.
5. Verify: biflows appear in pmacct output with correct 5-tuple, separate
   initiator/responder byte/packet counts, timestamps, TCP flags, and action.
6. Verify: IPv6 biflows work.
7. Verify: sampling at 1:10 reduces reported packet counts by ~10x.
8. Verify: `-D ingress` only captures inbound flows, `-D egress` only outbound.
9. Verify: reverse IEs (PEN 29305) are decoded correctly by pmacct.

### 11.3 Stress Testing

1. Use `pktgen` or `trafgen` to push 500 Kpps through TAP.
2. Confirm: no packet drops (XDP_PASS), CPU < 5%, flow map does not
   overflow (LRU eviction works).
3. Confirm: IPFIX messages arrive at collector without gaps
   (check sequence numbers).

---

## 12. Acceptance Criteria

- [ ] Daemon starts, attaches XDP to a TAP interface, and exits cleanly on SIGTERM.
- [ ] Bidirectional flows (biflows) for TCP, UDP, ICMP over IPv4 and IPv6 are correctly captured with separate initiator/responder counters.
- [ ] pmacct receives valid IPFIX biflow data (RFC 5103) and decodes all IEs correctly, including reverse IEs (PEN 29305).
- [ ] Active timeout triggers export at the configured interval (±1s).
- [ ] Sampling mode at 1:100 reduces flow packet counts proportionally.
- [ ] Direction filter `-D ingress` captures only inbound traffic; `-D egress` only outbound; `-D both` captures all.
- [ ] ACCEPT/REJECT field reflects conntrack state.
- [ ] Under 500 Kpps sustained load: no dropped packets, CPU < 5%.
- [ ] Code compiles with `-Wall -Werror` on gcc 12+ and clang 14+.
- [ ] `README.md` documents build, usage, and pmacct integration.

---

## 13. Constraints & Decisions Already Made

These are **not negotiable**. Do not propose alternatives:

1. Language: **C** with libbpf CO-RE.
2. One daemon per TAP interface.
3. Flow aggregation in **kernel** (eBPF maps), not userspace.
4. **Bidirectional biflows** (RFC 5103) with normalized key. Configurable direction filter (both/ingress/egress).
5. Map type: `BPF_MAP_TYPE_LRU_HASH`, 64K max entries.
6. Export: **IPFIX over UDP only**, biflow encoding with reverse IEs (PEN 29305).
7. Active timeout only — no idle or TCP-state timeout.
8. Configuration via CLI arguments only.
9. Must work on Linux **≥ 6.1** with BTF.
10. Test against **pmacct** collector.

---

## 14. Open Questions for Developer

None. All design decisions have been made. If you encounter an ambiguity
during implementation, **stop and ask** before making assumptions.
