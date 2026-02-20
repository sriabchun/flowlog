/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FLOW_H
#define FLOW_H

/*
 * Shared data structures between XDP (kernel) and userspace.
 * Used by both nft_flow_xdp.bpf.c and nft_flow_log.c.
 *
 * BPF side uses linux/ headers directly instead of vmlinux.h.
 * This is possible because we don't use CO-RE field relocations
 * (BPF_CORE_READ) — our XDP program only uses manually-defined
 * packet header structs with fixed offsets.
 */

#include <linux/types.h>
#include <linux/in6.h>
typedef __u32 __be32;

#define MAX_FLOWS       65536
#define ETH_ALEN        6

/* Direction filter values (stored in BPF global variables) */
#define DIR_BOTH        0
#define DIR_INGRESS     1
#define DIR_EGRESS      2

/* Normalized biflow key — lower IP:port is always initiator */
struct flow_key {
    __u8  family;       /* AF_INET or AF_INET6 */
    __u8  protocol;     /* IPPROTO_TCP, UDP, ICMP, etc. */
    __u16 init_port;    /* initiator port */
    __u16 resp_port;    /* responder port */
    __u16 _pad;
    union {
        __be32          v4;
        struct in6_addr v6;
    } init_addr;
    union {
        __be32          v4;
        struct in6_addr v6;
    } resp_addr;
};

/* Biflow counters — separate for each direction */
struct flow_value {
    __u64 init_packets;
    __u64 init_bytes;
    __u64 resp_packets;
    __u64 resp_bytes;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u32 init_tcp_flags;   /* widened to 32-bit for BPF atomic ops */
    __u32 resp_tcp_flags;
};

/* Ring buffer event: expired flow pushed by BPF timer callback */
struct flow_event {
    struct flow_key key;
    struct flow_value val;
};

#endif /* FLOW_H */
