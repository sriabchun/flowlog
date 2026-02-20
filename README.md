# flowlog

eBPF/XDP-based flow collector daemon for network interfaces. Captures bidirectional network flows (biflows) and exports them via IPFIX (RFC 7011 + RFC 5103) over UDP.

Comparable to AWS VPC Flow Logs. Works on any Linux network interface (TAP, veth, physical NICs) on kernel ≥ 6.1.

## Features

- **XDP-accelerated** flow capture with multi-buffer support (SKB mode for any NIC, native mode for supported drivers, jumbo frames via `xdp.frags`)
- **Kernel-side aggregation** using eBPF LRU hash maps (64K flows, ~4 MB)
- **Event-driven export** — BPF timers detect per-flow idle timeout, push expired flows to a ring buffer; userspace consumes via `epoll` with zero polling overhead
- **Bidirectional biflows** (RFC 5103) with separate initiator/responder counters
- **IPFIX export** over UDP with standard + reverse IEs (PEN 29305)
- **Direction filtering** — capture both, ingress only, or egress only
- **ACCEPT/REJECT** determination via conntrack (best-effort)
- **Packet sampling** — static (1:N) or dynamic auto-scaling targeting 250 Kpps
- **IPv4 + IPv6** dual-stack with extension header and fragment handling
- **VLAN support** — 802.1Q and QinQ (double-tagged) frames
- **Auto-detach** — XDP program auto-detaches on crash/SIGKILL via BPF link
- **Bloom filter** pre-check skips expensive hash lookups for new flows (map-of-maps with per-cycle reset)
- **Zero-overhead config** — BPF global variables eliminate per-packet map lookups for sample rate, direction filter, and MAC address
- **Suspend-safe timestamps** — `CLOCK_BOOTTIME` survives system suspend/hibernate

## Requirements

- Linux kernel ≥ 6.1 with BTF enabled (`/sys/kernel/btf/vmlinux`)
- clang ≥ 14 and llvm
- libbpf-dev
- bpftool
- libelf-dev
- zlib1g-dev
- libnetfilter-conntrack-dev

### Debian/Ubuntu

```bash
apt install clang llvm libbpf-dev linux-tools-common \
    libelf-dev zlib1g-dev libnetfilter-conntrack-dev
```

## Build

```bash
make
```

The binary is placed at `build/flowlog`.

## Usage

```
flowlog -i <interface> [-c <collector_ip>:<port>] [options]

Required:
  -i <ifname>       Network interface (e.g. tap0, eth0, ens3)

Optional:
  -c <ip:port>      IPFIX collector address (e.g. 10.0.0.1:4739 or [::1]:4739)
                    If omitted, flows are printed to stderr.
  -t <seconds>      Active timeout (default: 60)
  -s <rate>         Sampling rate: N (static 1:N), or auto:MIN:MAX (dynamic).
                    Dynamic mode targets 250 Kpps effective rate, adjusting
                    the sampling ratio between 1:MIN and 1:MAX each cycle.
                    Default: 1 (no sampling). Example: -s auto:1:1000
  -D <direction>    Direction filter: both|ingress|egress (default: both)
  -N                Use native XDP mode (requires driver support;
                    default is SKB/generic mode which works on any NIC)
  -P                Use per-CPU flow map (eliminates lock contention on
                    multi-queue NICs; uses more memory: ~4 MB × num_cpus).
                    Disables BPF timer mode — falls back to batch drain.
  -d <domain_id>    IPFIX Observation Domain ID (default: 0)
  -v                Verbose logging
  -h                Help
```

### Examples

```bash
# TAP interface: collect all traffic, export to collector
sudo ./build/flowlog -i tap0 -c 10.0.0.1:4739

# Physical NIC with native XDP (mlx5, i40e, virtio-net, etc.)
sudo ./build/flowlog -i eth0 -c 10.0.0.1:4739 -N

# Maximum performance: native XDP + per-CPU map + dynamic sampling
sudo ./build/flowlog -i eth0 -c 10.0.0.1:4739 -N -P -s auto:1:1000

# Print flows to stderr (no collector, any interface)
sudo ./build/flowlog -i ens3 -t 10

# With 30s timeout, sampling 1:100, egress only
sudo ./build/flowlog -i tap0 -c 10.0.0.1:4739 -t 30 -s 100 -D egress -v
```

## pmacct Integration

### pmacctd Configuration

Create `/etc/pmacct/nfacctd.conf`:

```
daemonize: false
nfacctd_ip: 0.0.0.0
nfacctd_port: 4739
plugins: print[flows]
print_output_file[flows]: /tmp/flows.txt
print_refresh_time[flows]: 30
aggregate[flows]: src_host, dst_host, src_port, dst_port, proto, tos
```

Run the collector:

```bash
nfacctd -f /etc/pmacct/nfacctd.conf
```

Then start flowlog pointing at the collector:

```bash
sudo ./build/flowlog -i tap0 -c 127.0.0.1:4739 -v
```

## Architecture

```
                          ┌────────────────────────┐
VM (tap0) → XDP program → │ BPF LRU hash map (64K) │
                          └──────────┬─────────────┘
                    BPF timer fires  │  OR  Userspace batch drain (-P)
                                     ▼
                          ┌──────────────────┐
                          │    Ring buffer    │
                          └────────┬─────────┘
                                   ▼
                          Userspace daemon → conntrack → IPFIX/UDP → Collector
```

- XDP program parses packets (IPv4/IPv6, VLAN/QinQ, extension headers, fragments), normalizes 5-tuple into biflow key, updates per-direction counters with atomic operations
- Bloom filter pre-check (via map-of-maps) skips expensive hash lookups for new flows
- BPF timers arm on flow creation; when a flow goes idle for `-t` seconds, the timer callback pushes it to a ring buffer and deletes it from the map
- Userspace consumes the ring buffer event-driven via `ring_buffer__poll` — no periodic map drain needed
- Per-CPU mode (`-P`) disables BPF timers and falls back to periodic `bpf_map_lookup_and_delete_batch`
- Direction determined by comparing packet source MAC against the interface MAC (BPF global, no map lookup)
- BPF link-based XDP attachment ensures auto-detach on process crash or SIGKILL
- Config (sample rate, direction filter, MAC) stored as BPF global variables — zero per-packet map lookups
- Timestamps use `CLOCK_BOOTTIME` (survives suspend/hibernate)

## IPFIX Information Elements

| Field | IE ID | Direction |
|---|---|---|
| sourceIPv4/v6Address | 8/27 | Forward |
| destinationIPv4/v6Address | 12/28 | Forward |
| sourceTransportPort | 7 | Forward |
| destinationTransportPort | 11 | Forward |
| protocolIdentifier | 4 | Forward |
| packetDeltaCount | 2 | Forward |
| octetDeltaCount | 1 | Forward |
| flowStartMilliseconds | 152 | Shared |
| flowEndMilliseconds | 153 | Shared |
| tcpControlBits | 6 | Forward |
| firewallEvent | 233 | Shared |
| packetDeltaCount (PEN 29305) | 2 | Reverse |
| octetDeltaCount (PEN 29305) | 1 | Reverse |
| tcpControlBits (PEN 29305) | 6 | Reverse |
| biflowDirection | 239 | Shared |

## File Structure

```
flowlog/
├── Makefile
├── README.md
├── flow-log.md              # Specification
└── src/
    ├── flowlog_xdp.bpf.c   # XDP/eBPF kernel program
    ├── flowlog.c            # Userspace daemon (main)
    ├── ipfix.c               # IPFIX encoding + UDP export
    ├── ipfix.h
    ├── flow.h                # Shared data structures
    ├── conntrack.c           # ACCEPT/REJECT via conntrack
    └── conntrack.h
```

## License

GPL-2.0-or-later
