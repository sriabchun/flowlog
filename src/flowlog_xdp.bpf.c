// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * flowlog_xdp.bpf.c — XDP program for biflow collection on TAP interfaces.
 *
 * Parses L2/L3/L4, normalizes 5-tuple into a biflow key, and updates
 * per-direction counters in an LRU hash map. Purely passive (XDP_PASS).
 *
 * Uses linux/ headers directly — no vmlinux.h, no CO-RE relocations.
 */

#ifndef __BPF__
#define __BPF__
#endif

#include <linux/bpf.h>
#include "flow.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* --- Map definitions --- */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} flow_map SEC(".maps");

/* --- Global config (replaces config_map / vm_mac_map) ---
 * Writable globals (.data/.bss) are mmap'd; userspace writes take
 * effect immediately with no syscall overhead.  sample_rate lives
 * in .data because dynamic sampling mutates it at runtime.  The
 * rest are const volatile (.rodata) — frozen after load.
 */
volatile __u32 cfg_sample_rate = 1;

const volatile __u32 cfg_dir_filter  = 0;  /* DIR_BOTH */
const volatile __u32 cfg_dyn_enabled = 0;
const volatile __u8  cfg_vm_mac[ETH_ALEN] = {};
const volatile __u64 cfg_timeout_ns  = 60000000000ULL; /* 60s */
const volatile __u32 cfg_use_timer   = 1; /* 0 for percpu (no timer support) */

/* Per-CPU sampling counter */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} sample_cnt SEC(".maps");

/* Per-CPU total packet counter (for dynamic sampling — counts all packets) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} pkt_counter SEC(".maps");

/* Bloom filter for fast "definitely new flow" detection.
 * Avoids the expensive failed LRU hash lookup on new-flow creation.
 * Wrapped in ARRAY_OF_MAPS so userspace can atomically swap in a
 * fresh bloom filter after each flush (bloom filters have no delete). */
struct bloom_inner {
    __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
    __uint(max_entries, MAX_FLOWS);
    __uint(map_extra, 3);           /* number of hash functions */
    __type(value, struct flow_key);
} flow_bloom_inner SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __array(values, struct bloom_inner);
} bloom_outer SEC(".maps") = {
    .values = { &flow_bloom_inner },
};

/* Per-flow idle timer (separate map so flow_map can be percpu).
 * Guarded by cfg_use_timer — when 0 the verifier prunes all timer
 * code paths, so this map stays empty in percpu mode. */
struct timer_val {
    struct bpf_timer timer;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct timer_val);
} timer_map SEC(".maps");

/* Ring buffer for expired-flow events (timer → userspace) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024); /* 2 MB */
} flow_events SEC(".maps");

/* Timer callback: fires when a flow is expected to have gone idle.
 * Checks last_seen_ns; if still active, re-arms.  Otherwise pushes
 * the flow to the ring buffer and deletes it from both maps. */
static int flow_timer_cb(void *map, void *key, void *value)
{
    struct flow_key *fkey = key;
    struct timer_val *tv = value;

    struct flow_value *val = bpf_map_lookup_elem(&flow_map, fkey);
    if (!val) {
        /* Flow evicted by LRU — clean up orphaned timer */
        bpf_map_delete_elem(map, fkey);
        return 0;
    }

    __u64 now = bpf_ktime_get_boot_ns();
    __u64 idle_ns = now - val->last_seen_ns;

    if (idle_ns < cfg_timeout_ns) {
        /* Flow still active, re-arm for remaining time */
        bpf_timer_start(&tv->timer, cfg_timeout_ns - idle_ns, 0);
        return 0;
    }

    /* Flow idle — push to ring buffer */
    struct flow_event *evt =
        bpf_ringbuf_reserve(&flow_events, sizeof(*evt), 0);
    if (!evt) {
        /* Ring buffer full, retry in 1 second */
        bpf_timer_start(&tv->timer, 1000000000ULL, 0);
        return 0;
    }

    __builtin_memcpy(&evt->key, fkey, sizeof(evt->key));
    __builtin_memcpy(&evt->val, val, sizeof(evt->val));
    bpf_ringbuf_submit(evt, 0);

    /* Delete timer_map first so arm_flow_timer's BPF_NOEXIST succeeds
     * if a new flow with the same key is created between the two deletes */
    bpf_map_delete_elem(map, fkey);
    bpf_map_delete_elem(&flow_map, fkey);
    return 0;
}

/* --- Header structs (from vmlinux.h via CO-RE, but we define minimal versions
       for clarity and verifier compatibility) --- */

struct ethhdr_min {
    __u8  h_dest[ETH_ALEN];
    __u8  h_source[ETH_ALEN];
    __u16 h_proto;
} __attribute__((packed));

struct iphdr_min {
    __u8  ihl_ver;
    __u8  tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
} __attribute__((packed));

/* Not packed: already 40 bytes with no padding (fields naturally aligned).
 * Avoiding packed so &saddr/&daddr can be taken without alignment warnings. */
struct ipv6hdr_min {
    __u32          flow_lbl_ver;
    __u16          payload_len;
    __u8           nexthdr;
    __u8           hop_limit;
    struct in6_addr saddr;
    struct in6_addr daddr;
};

struct tcphdr_min {
    __u16 source;
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;
    __u16 flags;    /* data offset + flags */
} __attribute__((packed));

struct udphdr_min {
    __u16 source;
    __u16 dest;
    __u16 len;
    __u16 check;
} __attribute__((packed));

struct icmphdr_min {
    __u8  type;
    __u8  code;
    __u16 checksum;
} __attribute__((packed));

struct vlan_hdr {
    __u16 tci;      /* PCP(3) + DEI(1) + VID(12) */
    __u16 h_proto;  /* next EtherType */
} __attribute__((packed));

/* IPv6 extension header (common format for hop-by-hop, routing, destination) */
struct ipv6_ext_hdr {
    __u8 nexthdr;
    __u8 hdrlen;    /* length in 8-octet units, not including first 8 octets */
} __attribute__((packed));

/* IPv6 fragment header (nexthdr=44) */
struct ipv6_frag_hdr {
    __u8  nexthdr;
    __u8  reserved;
    __u16 frag_off_flags;
    __u32 identification;
} __attribute__((packed));

/* Check if nexthdr is a known extension header that can be skipped */
static __always_inline int is_ipv6_ext_hdr(__u8 nexthdr)
{
    return nexthdr == 0   /* Hop-by-Hop */
        || nexthdr == 43  /* Routing */
        || nexthdr == 44  /* Fragment */
        || nexthdr == 60; /* Destination Options */
}

/* --- Helpers --- */

/* Compare two IPv4 addresses. Returns <0, 0, >0. */
static __always_inline int cmp_v4(__be32 a, __be32 b)
{
    __u32 ha = bpf_ntohl(a);
    __u32 hb = bpf_ntohl(b);
    if (ha < hb) return -1;
    if (ha > hb) return 1;
    return 0;
}

/* Compare two IPv6 addresses byte-by-byte. Returns <0, 0, >0. */
static __always_inline int cmp_v6(const struct in6_addr *a,
                                   const struct in6_addr *b)
{
    const __u8 *ab = (const __u8 *)a;
    const __u8 *bb = (const __u8 *)b;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (ab[i] < bb[i]) return -1;
        if (ab[i] > bb[i]) return 1;
    }
    return 0;
}

/* Extract TCP flags (FIN..CWR = lower 8 bits of the flags field) */
static __always_inline __u8 tcp_flags(__u16 flags_field)
{
    return bpf_ntohs(flags_field) & 0xFF;
}

/* Check if src MAC matches VM MAC */
static __always_inline int is_from_vm(const __u8 *src_mac)
{
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        if (src_mac[i] != cfg_vm_mac[i])
            return 0;
    }
    return 1;
}

/* Update an existing flow entry's counters */
static __always_inline void update_flow(struct flow_value *val,
                                         int is_initiator, __u32 l3_len,
                                         __u8 tcp_fl, __u64 now)
{
    if (is_initiator) {
        __sync_fetch_and_add(&val->init_packets, 1);
        __sync_fetch_and_add(&val->init_bytes, l3_len);
        __sync_fetch_and_or(&val->init_tcp_flags, tcp_fl);
    } else {
        __sync_fetch_and_add(&val->resp_packets, 1);
        __sync_fetch_and_add(&val->resp_bytes, l3_len);
        __sync_fetch_and_or(&val->resp_tcp_flags, tcp_fl);
    }
    __sync_lock_test_and_set(&val->last_seen_ns, now);
}

/* Arm a BPF timer for per-flow idle detection (non-percpu only) */
static __always_inline void arm_flow_timer(const struct flow_key *fkey)
{
    struct timer_val tv = {};
    bpf_map_update_elem(&timer_map, fkey, &tv, BPF_NOEXIST);
    struct timer_val *tvp = bpf_map_lookup_elem(&timer_map, fkey);
    if (tvp) {
        bpf_timer_init(&tvp->timer, &timer_map, 7 /* CLOCK_BOOTTIME */);
        bpf_timer_set_callback(&tvp->timer, flow_timer_cb);
        bpf_timer_start(&tvp->timer, cfg_timeout_ns, 0);
    }
}

/* Check sampling: returns 1 if this packet should be processed */
static __always_inline int sample_check(void)
{
    __u32 rate = cfg_sample_rate;
    if (rate <= 1)
        return 1;

    __u32 zero = 0;
    __u32 *cnt = bpf_map_lookup_elem(&sample_cnt, &zero);
    if (!cnt)
        return 1;

    __u32 cur = *cnt + 1;
    if (cur >= rate)
        cur = 0;
    *cnt = cur;

    return (cur == 0);
}

/* --- Main XDP program --- */

SEC("xdp.frags")
int flowlog_xdp(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Parse Ethernet */
    struct ethhdr_min *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Determine direction */
    int egress = is_from_vm(eth->h_source);

    /* Check direction filter */
    if (cfg_dir_filter == DIR_INGRESS && egress)
        return XDP_PASS;
    if (cfg_dir_filter == DIR_EGRESS && !egress)
        return XDP_PASS;

    /* Count total packets only if dynamic sampling is enabled */
    if (cfg_dyn_enabled) {
        __u32 pkt_key = 0;
        __u64 *pkt_cnt = bpf_map_lookup_elem(&pkt_counter, &pkt_key);
        if (pkt_cnt)
            (*pkt_cnt)++;
    }

    /* Sampling */
    if (!sample_check())
        return XDP_PASS;

    __u16 eth_proto = eth->h_proto;
    void *l3 = (void *)(eth + 1);

    /* Strip VLAN tags (802.1Q and QinQ) */
    #pragma unroll
    for (int vlan_i = 0; vlan_i < 2; vlan_i++) {
        if (eth_proto != bpf_htons(0x8100) &&
            eth_proto != bpf_htons(0x88A8))
            break;
        struct vlan_hdr *vhdr = l3;
        if ((void *)(vhdr + 1) > data_end)
            return XDP_PASS;
        eth_proto = vhdr->h_proto;
        l3 = (void *)(vhdr + 1);
    }

    struct flow_key fkey = {};
    __u16 src_port = 0, dst_port = 0;
    __u8  tcp_fl = 0;
    __u32 l3_len = 0;
    int   is_initiator = 1;

    if (eth_proto == bpf_htons(0x0800)) {
        /* IPv4 */
        struct iphdr_min *ip = l3;
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        fkey.family   = 2; /* AF_INET */
        fkey.protocol = ip->protocol;
        l3_len = bpf_ntohs(ip->tot_len);

        /* Parse L4 (only for first fragment or non-fragmented packets) */
        __u8 ihl = (ip->ihl_ver & 0x0F) * 4;
        if (ihl < 20)
            return XDP_PASS;
        void *l4 = l3 + ihl;
        int is_fragment = bpf_ntohs(ip->frag_off) & 0x1FFF;

        if (!is_fragment) {
            if (fkey.protocol == 6) { /* TCP */
                struct tcphdr_min *tcp = l4;
                if ((void *)(tcp + 1) > data_end)
                    return XDP_PASS;
                src_port = tcp->source;
                dst_port = tcp->dest;
                tcp_fl = tcp_flags(tcp->flags);
            } else if (fkey.protocol == 17) { /* UDP */
                struct udphdr_min *udp = l4;
                if ((void *)(udp + 1) > data_end)
                    return XDP_PASS;
                src_port = udp->source;
                dst_port = udp->dest;
            } else if (fkey.protocol == 1) { /* ICMP */
                struct icmphdr_min *icmp = l4;
                if ((void *)(icmp + 1) > data_end)
                    return XDP_PASS;
                /* ICMP type/code are asymmetric across directions
                 * (e.g. echo request type=8 vs reply type=0), so
                 * using them as ports would prevent biflow merging.
                 * Leave ports as 0 to merge both directions. */
            }
        }
        /* Non-first fragments: ports stay 0, still counted by IP 5-tuple */

        /* Normalize: lower IP = initiator */
        int cmp = cmp_v4(ip->saddr, ip->daddr);
        if (cmp < 0 || (cmp == 0 && bpf_ntohs(src_port) <= bpf_ntohs(dst_port))) {
            fkey.init_addr.v4 = ip->saddr;
            fkey.resp_addr.v4 = ip->daddr;
            fkey.init_port    = src_port;
            fkey.resp_port    = dst_port;
            is_initiator      = 1;
        } else {
            fkey.init_addr.v4 = ip->daddr;
            fkey.resp_addr.v4 = ip->saddr;
            fkey.init_port    = dst_port;
            fkey.resp_port    = src_port;
            is_initiator      = 0;
        }

    } else if (eth_proto == bpf_htons(0x86DD)) {
        /* IPv6 */
        struct ipv6hdr_min *ip6 = l3;
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        fkey.family   = 10; /* AF_INET6 */
        __u8 nexthdr  = ip6->nexthdr;
        l3_len = bpf_ntohs(ip6->payload_len) + 40;

        void *l4 = (void *)(ip6 + 1);
        int is_v6_fragment = 0;

        /* Skip IPv6 extension headers (bounded to satisfy BPF verifier) */
        #pragma unroll
        for (int ext_i = 0; ext_i < 6; ext_i++) {
            if (!is_ipv6_ext_hdr(nexthdr))
                break;
            if (nexthdr == 44) {
                /* Fragment header */
                struct ipv6_frag_hdr *frag = l4;
                if ((void *)(frag + 1) > data_end)
                    return XDP_PASS;
                nexthdr = frag->nexthdr;
                l4 = (void *)(frag + 1);
                /* Non-first fragments: skip L4, count with ports=0 */
                if (bpf_ntohs(frag->frag_off_flags) & 0xFFF8) {
                    is_v6_fragment = 1;
                    break;  /* no point parsing further ext headers */
                }
            } else {
                struct ipv6_ext_hdr *ext = l4;
                if ((void *)(ext + 1) > data_end)
                    return XDP_PASS;
                nexthdr = ext->nexthdr;
                l4 = (void *)ext + (ext->hdrlen + 1) * 8;
                if (l4 > data_end)
                    return XDP_PASS;
            }
        }

        fkey.protocol = nexthdr;

        if (!is_v6_fragment) {
            if (fkey.protocol == 6) { /* TCP */
                struct tcphdr_min *tcp = l4;
                if ((void *)(tcp + 1) > data_end)
                    return XDP_PASS;
                src_port = tcp->source;
                dst_port = tcp->dest;
                tcp_fl = tcp_flags(tcp->flags);
            } else if (fkey.protocol == 17) { /* UDP */
                struct udphdr_min *udp = l4;
                if ((void *)(udp + 1) > data_end)
                    return XDP_PASS;
                src_port = udp->source;
                dst_port = udp->dest;
            } else if (fkey.protocol == 58) { /* ICMPv6 */
                struct icmphdr_min *icmp = l4;
                if ((void *)(icmp + 1) > data_end)
                    return XDP_PASS;
                /* Same as IPv4 ICMP: leave ports as 0 for biflow merging */
            }
        }
        /* Non-first fragments: ports stay 0, still counted by IP 5-tuple */

        /* Normalize: lower IPv6 = initiator */
        int cmp = cmp_v6(&ip6->saddr, &ip6->daddr);
        if (cmp < 0 || (cmp == 0 && bpf_ntohs(src_port) <= bpf_ntohs(dst_port))) {
            fkey.init_addr.v6 = ip6->saddr;
            fkey.resp_addr.v6 = ip6->daddr;
            fkey.init_port    = src_port;
            fkey.resp_port    = dst_port;
            is_initiator      = 1;
        } else {
            fkey.init_addr.v6 = ip6->daddr;
            fkey.resp_addr.v6 = ip6->saddr;
            fkey.init_port    = dst_port;
            fkey.resp_port    = src_port;
            is_initiator      = 0;
        }

    } else {
        /* Not IP — skip (ARP, etc.) */
        return XDP_PASS;
    }

    /* Lookup or create flow entry.
     * Bloom filter fast-path: if the key is definitely not in the
     * map, skip the expensive failed LRU hash lookup (~200 cycles)
     * and go straight to insert.  The bloom filter is accessed via
     * map-of-maps so userspace can swap in a fresh one each cycle. */
    __u64 now = bpf_ktime_get_boot_ns();

    __u32 bloom_key = 0;
    void *bloom = bpf_map_lookup_elem(&bloom_outer, &bloom_key);
    int in_bloom = bloom && (bpf_map_peek_elem(bloom, &fkey) == 0);

    struct flow_value *val = NULL;
    if (in_bloom)
        val = bpf_map_lookup_elem(&flow_map, &fkey);

    if (val) {
        update_flow(val, is_initiator, l3_len, tcp_fl, now);
    } else {
        /* Try to create new entry */
        struct flow_value new_val = {};
        new_val.first_seen_ns = now;
        new_val.last_seen_ns  = now;

        if (is_initiator) {
            new_val.init_packets   = 1;
            new_val.init_bytes     = l3_len;
            new_val.init_tcp_flags = tcp_fl;
        } else {
            new_val.resp_packets   = 1;
            new_val.resp_bytes     = l3_len;
            new_val.resp_tcp_flags = tcp_fl;
        }

        int ret = bpf_map_update_elem(&flow_map, &fkey, &new_val, BPF_NOEXIST);
        if (ret < 0) {
            /* Entry exists (bloom stale after reset) — update instead */
            val = bpf_map_lookup_elem(&flow_map, &fkey);
            if (val)
                update_flow(val, is_initiator, l3_len, tcp_fl, now);
        } else {
            /* New entry created — register in bloom filter and arm timer */
            if (bloom)
                bpf_map_push_elem(bloom, &fkey, 0);
            if (cfg_use_timer)
                arm_flow_timer(&fkey);
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
