// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * flowlog.c — Userspace daemon for flowlog.
 *
 * Loads XDP BPF program onto a network interface, periodically reads
 * aggregated biflows from the BPF map, and exports them via IPFIX/UDP
 * or prints to stderr.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "flow.h"
#include "ipfix.h"
#include "conntrack.h"
#include "flowlog_xdp.skel.h"

static volatile int running = 1;
static int verbose;

#define DYN_SAMPLE_TARGET_PPS 250000  /* target effective PPS */

struct dyn_sample {
    int      enabled;
    uint32_t min_rate;
    uint32_t max_rate;
    uint32_t current_rate;
};

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -i <ifname> [-c <ip:port>] [options]\n"
        "\n"
        "Required:\n"
        "  -i <ifname>       Network interface (e.g. tap0, eth0)\n"
        "\n"
        "Optional:\n"
        "  -c <ip:port>      IPFIX collector address (omit to print to stderr)\n"
        "  -t <seconds>      Active timeout (default: 60)\n"
        "  -s <rate>         Sampling rate: N (static 1:N) or auto:MIN:MAX (dynamic)\n"
        "  -D <direction>    Direction filter: both|ingress|egress (default: both)\n"
        "  -N                Use native XDP mode (requires driver support)\n"
        "  -P                Use per-CPU flow map (higher performance, more memory)\n"
        "  -d <domain_id>    IPFIX Observation Domain ID (default: 0)\n"
        "  -v                Verbose logging\n"
        "  -h                Help\n",
        prog);
}

/* Get MAC address of the interface (used for direction detection) */
static int get_if_mac(const char *ifname, uint8_t mac[ETH_ALEN])
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(fd);
        return -1;
    }
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    return 0;
}

/* Read the per-CPU packet counter. Returns total across all CPUs. */
static uint64_t read_pkt_counter(int map_fd, int num_cpus)
{
    uint32_t key = 0;
    uint64_t *vals = calloc(num_cpus, sizeof(uint64_t));
    if (!vals)
        return 0;

    uint64_t total = 0;
    if (bpf_map_lookup_elem(map_fd, &key, vals) == 0) {
        for (int i = 0; i < num_cpus; i++)
            total += vals[i];
    }

    free(vals);
    return total;
}

/* Update dynamic sampling rate based on observed PPS */
static void update_dynamic_sample(struct dyn_sample *ds, uint64_t total_pkts,
                                   int interval_sec, volatile uint32_t *bpf_rate)
{
    if (!ds->enabled || interval_sec <= 0)
        return;

    uint64_t pps = total_pkts / (uint64_t)interval_sec;
    uint32_t new_rate;

    if (pps <= DYN_SAMPLE_TARGET_PPS) {
        new_rate = ds->min_rate;
    } else {
        new_rate = (uint32_t)(pps / DYN_SAMPLE_TARGET_PPS);
        if (new_rate < ds->min_rate)
            new_rate = ds->min_rate;
        if (new_rate > ds->max_rate)
            new_rate = ds->max_rate;
    }

    if (new_rate != ds->current_rate) {
        ds->current_rate = new_rate;
        *bpf_rate = new_rate;
        if (verbose)
            fprintf(stderr, "dynamic sampling: %llu pps -> rate 1:%u\n",
                    (unsigned long long)pps, new_rate);
    }
}

/* Print a single flow to stderr in human-readable format */
static void print_flow(const struct flow_key *key, const struct flow_value *val,
                       uint8_t action, int64_t mono_to_epoch_ns)
{
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    int af = (key->family == 2) ? AF_INET : AF_INET6;

    inet_ntop(af, (key->family == 2) ? (void *)&key->init_addr.v4
                                     : (void *)&key->init_addr.v6,
              src, sizeof(src));
    inet_ntop(af, (key->family == 2) ? (void *)&key->resp_addr.v4
                                     : (void *)&key->resp_addr.v6,
              dst, sizeof(dst));

    uint64_t start_ms = ktime_to_epoch_ms(val->first_seen_ns, mono_to_epoch_ns);
    uint64_t end_ms   = ktime_to_epoch_ms(val->last_seen_ns, mono_to_epoch_ns);

    fprintf(stderr,
        "%s %s:%u -> %s:%u proto=%u "
        "init(pkts=%llu bytes=%llu flags=0x%02x) "
        "resp(pkts=%llu bytes=%llu flags=0x%02x) "
        "start=%llu end=%llu action=%s\n",
        (key->family == 2) ? "IPv4" : "IPv6",
        src, ntohs(key->init_port), dst, ntohs(key->resp_port),
        key->protocol,
        (unsigned long long)val->init_packets,
        (unsigned long long)val->init_bytes,
        val->init_tcp_flags,
        (unsigned long long)val->resp_packets,
        (unsigned long long)val->resp_bytes,
        val->resp_tcp_flags,
        (unsigned long long)start_ms, (unsigned long long)end_ms,
        (action == FW_EVENT_ACCEPT) ? "ACCEPT" : "REJECT");
}

/* Merge per-CPU flow values into a single aggregated value */
static void merge_percpu_values(struct flow_value *out,
                                const struct flow_value *pcpu, int num_cpus)
{
    memset(out, 0, sizeof(*out));
    out->first_seen_ns = UINT64_MAX;

    for (int c = 0; c < num_cpus; c++) {
        out->init_packets += pcpu[c].init_packets;
        out->init_bytes   += pcpu[c].init_bytes;
        out->resp_packets += pcpu[c].resp_packets;
        out->resp_bytes   += pcpu[c].resp_bytes;
        out->init_tcp_flags |= pcpu[c].init_tcp_flags;
        out->resp_tcp_flags |= pcpu[c].resp_tcp_flags;

        if (pcpu[c].first_seen_ns && pcpu[c].first_seen_ns < out->first_seen_ns)
            out->first_seen_ns = pcpu[c].first_seen_ns;
        if (pcpu[c].last_seen_ns > out->last_seen_ns)
            out->last_seen_ns = pcpu[c].last_seen_ns;
    }

    if (out->first_seen_ns == UINT64_MAX)
        out->first_seen_ns = 0;
}

/* Replace the bloom filter with a fresh empty one.
 * Bloom filters don't support deletion, so we create a new map and
 * swap it into the outer array-of-maps.  The BPF program atomically
 * picks up the new inner map on its next lookup. */
static void reset_bloom_filter(int bloom_outer_fd)
{
    LIBBPF_OPTS(bpf_map_create_opts, opts, .map_extra = 3);
    int new_fd = bpf_map_create(BPF_MAP_TYPE_BLOOM_FILTER, "bloom",
                                0, sizeof(struct flow_key), MAX_FLOWS,
                                &opts);
    if (new_fd < 0) {
        perror("bloom filter create");
        return;
    }

    uint32_t zero = 0;
    if (bpf_map_update_elem(bloom_outer_fd, &zero, &new_fd, BPF_ANY) < 0)
        perror("bloom filter swap");

    close(new_fd);
}

/* --- Ring buffer consumer (timer mode) --- */

struct export_ctx {
    struct flow_key *keys;
    struct flow_value *vals;
    uint8_t *actions;
    int count;
    int cap;
};

static int ringbuf_event_cb(void *ctx, void *data, size_t data_sz)
{
    struct export_ctx *ectx = ctx;
    struct flow_event *evt = data;

    if (data_sz < sizeof(*evt))
        return 0;

    if (ectx->count >= ectx->cap) {
        int new_cap = ectx->cap * 2;
        void *new_keys, *new_vals, *new_actions;

        new_keys = realloc(ectx->keys, new_cap * sizeof(*ectx->keys));
        new_vals = realloc(ectx->vals, new_cap * sizeof(*ectx->vals));
        new_actions = realloc(ectx->actions, new_cap);
        if (!new_keys || !new_vals || !new_actions) {
            /* On partial failure, keep the original (smaller) buffers.
             * realloc guarantees originals are untouched on failure. */
            if (new_keys) ectx->keys = new_keys;
            if (new_vals) ectx->vals = new_vals;
            if (new_actions) ectx->actions = new_actions;
            return -1;
        }
        ectx->keys = new_keys;
        ectx->vals = new_vals;
        ectx->actions = new_actions;
        ectx->cap = new_cap;
    }

    ectx->keys[ectx->count] = evt->key;
    ectx->vals[ectx->count] = evt->val;
    ectx->actions[ectx->count] = conntrack_lookup(&evt->key);
    ectx->count++;

    return 0;
}

static void export_batch(struct export_ctx *ectx, struct ipfix_exporter *exp,
                          int64_t mono_to_epoch_ns)
{
    if (ectx->count == 0)
        return;

    if (verbose)
        fprintf(stderr, "exporting %d biflows (ringbuf)\n", ectx->count);

    if (exp) {
        ipfix_export_flows(exp, ectx->keys, ectx->vals, ectx->actions,
                           ectx->count, mono_to_epoch_ns);
    } else {
        for (int i = 0; i < ectx->count; i++)
            print_flow(&ectx->keys[i], &ectx->vals[i],
                       ectx->actions[i], mono_to_epoch_ns);
    }

    ectx->count = 0;
}

/* Read all flows from the BPF map and export via IPFIX or print to stderr */
static int flush_flows(int map_fd, struct ipfix_exporter *exp,
                       int64_t mono_to_epoch_ns, int percpu, int num_cpus)
{
    /* Per-CPU maps return an array of num_cpus values per key */
    size_t val_size = percpu
        ? (size_t)num_cpus * sizeof(struct flow_value)
        : sizeof(struct flow_value);

    int cap = 4096;
    struct flow_key *keys = malloc(cap * sizeof(*keys));
    void *raw_vals = malloc(cap * val_size);
    struct flow_value *vals = malloc(cap * sizeof(*vals));
    uint8_t *actions = malloc(cap);
    if (!keys || !raw_vals || !vals || !actions) {
        free(keys); free(raw_vals); free(vals); free(actions);
        return -1;
    }

    /* Atomic batch lookup-and-delete: reads and removes entries in one
     * syscall per batch, eliminating the race window between read and
     * delete where BPF-side increments could be lost. */
    LIBBPF_OPTS(bpf_map_batch_opts, opts);
    int count = 0;
    void *in_batch = NULL;
    __u32 out_batch;

    for (;;) {
        __u32 batch_count = cap - count;
        if (batch_count == 0) {
            int new_cap = cap * 2;
            void *tmp;

            tmp = realloc(keys, new_cap * sizeof(*keys));
            if (!tmp) break;
            keys = tmp;

            tmp = realloc(raw_vals, new_cap * val_size);
            if (!tmp) break;
            raw_vals = tmp;

            tmp = realloc(vals, new_cap * sizeof(*vals));
            if (!tmp) break;
            vals = tmp;

            tmp = realloc(actions, new_cap);
            if (!tmp) break;
            actions = tmp;

            cap = new_cap;
            batch_count = cap - count;
        }

        int ret = bpf_map_lookup_and_delete_batch(map_fd,
            in_batch, &out_batch,
            keys + count,
            (uint8_t *)raw_vals + (size_t)count * val_size,
            &batch_count, &opts);

        count += batch_count;

        if (ret && errno == ENOENT)
            break;  /* all entries consumed */
        if (ret)
            break;  /* other error */

        in_batch = &out_batch;
    }

    /* Merge per-CPU values and resolve conntrack actions */
    for (int i = 0; i < count; i++) {
        if (percpu)
            merge_percpu_values(&vals[i],
                (struct flow_value *)((uint8_t *)raw_vals + (size_t)i * val_size),
                num_cpus);
        else
            vals[i] = ((struct flow_value *)raw_vals)[i];
        actions[i] = conntrack_lookup(&keys[i]);
    }

    if (verbose && count > 0)
        fprintf(stderr, "exporting %d biflows\n", count);

    int exported;
    if (exp) {
        exported = ipfix_export_flows(exp, keys, vals, actions, count, mono_to_epoch_ns);
    } else {
        for (int i = 0; i < count; i++)
            print_flow(&keys[i], &vals[i], actions[i], mono_to_epoch_ns);
        exported = count;
    }

    free(keys);
    free(raw_vals);
    free(vals);
    free(actions);

    return exported;
}

int main(int argc, char **argv)
{
    const char *ifname = NULL;
    const char *collector = NULL;
    int timeout_sec = 60;
    uint32_t sample_rate = 1;
    struct dyn_sample dyn = { .enabled = 0, .min_rate = 1,
                              .max_rate = 1000, .current_rate = 1 };
    uint32_t dir_filter = DIR_BOTH;
    uint32_t obs_domain = 0;
    uint32_t xdp_flags = XDP_FLAGS_SKB_MODE;
    int percpu = 0;
    int opt;

    while ((opt = getopt(argc, argv, "i:c:t:s:D:NPd:vh")) != -1) {
        switch (opt) {
        case 'i': ifname = optarg; break;
        case 'c': collector = optarg; break;
        case 't': timeout_sec = atoi(optarg); break;
        case 's':
            if (strncmp(optarg, "auto", 4) == 0) {
                dyn.enabled = 1;
                if (sscanf(optarg, "auto:%u:%u",
                           &dyn.min_rate, &dyn.max_rate) < 2) {
                    dyn.min_rate = 1;
                    dyn.max_rate = 1000;
                }
                dyn.current_rate = dyn.min_rate;
                sample_rate = dyn.min_rate;
            } else {
                sample_rate = atoi(optarg);
            }
            break;
        case 'D':
            if (strcmp(optarg, "ingress") == 0)
                dir_filter = DIR_INGRESS;
            else if (strcmp(optarg, "egress") == 0)
                dir_filter = DIR_EGRESS;
            else
                dir_filter = DIR_BOTH;
            break;
        case 'N': xdp_flags = XDP_FLAGS_DRV_MODE; break;
        case 'P': percpu = 1; break;
        case 'd': obs_domain = atoi(optarg); break;
        case 'v': verbose = 1; break;
        case 'h':
        default:
            usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    if (!ifname) {
        usage(argv[0]);
        return 1;
    }

    if (timeout_sec < 1) {
        fprintf(stderr, "error: timeout must be >= 1 second\n");
        return 1;
    }

    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "interface '%s' not found\n", ifname);
        return 1;
    }

    /* Get interface MAC (used to detect packet direction) */
    uint8_t vm_mac[ETH_ALEN];
    if (get_if_mac(ifname, vm_mac) < 0) {
        fprintf(stderr, "failed to get MAC for %s\n", ifname);
        return 1;
    }
    if (verbose)
        fprintf(stderr, "interface %s (index %d) MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                ifname, ifindex,
                vm_mac[0], vm_mac[1], vm_mac[2],
                vm_mac[3], vm_mac[4], vm_mac[5]);

    /* Initialize conntrack */
    conntrack_init();

    /* Initialize IPFIX exporter (only if collector specified) */
    struct ipfix_exporter exp;
    struct ipfix_exporter *exp_ptr = NULL;
    if (collector) {
        if (ipfix_init(&exp, collector, obs_domain) < 0)
            return 1;
        exp_ptr = &exp;
    }

    /* Open and load BPF */
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 1) {
        fprintf(stderr, "failed to get CPU count\n");
        return 1;
    }

    struct flowlog_xdp_bpf *skel = flowlog_xdp_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    /* Override map type to PERCPU_LRU_HASH if requested */
    if (percpu) {
        if (bpf_map__set_type(skel->maps.flow_map,
                              BPF_MAP_TYPE_LRU_PERCPU_HASH) < 0) {
            fprintf(stderr, "failed to set percpu map type\n");
            flowlog_xdp_bpf__destroy(skel);
            return 1;
        }
    }

    /* Set config via BPF globals BEFORE load — rodata is frozen at load time.
     * Timer mode is disabled for percpu maps (BPF timers don't support them). */
    skel->rodata->cfg_dir_filter = dir_filter;
    skel->rodata->cfg_dyn_enabled = dyn.enabled ? 1 : 0;
    memcpy((void *)skel->rodata->cfg_vm_mac, vm_mac, ETH_ALEN);
    skel->rodata->cfg_timeout_ns = (uint64_t)timeout_sec * 1000000000ULL;
    skel->rodata->cfg_use_timer = percpu ? 0 : 1;

    if (flowlog_xdp_bpf__load(skel)) {
        fprintf(stderr, "failed to load BPF program\n");
        flowlog_xdp_bpf__destroy(skel);
        return 1;
    }

    /* .data is writable after load (mmap'd) */
    skel->data->cfg_sample_rate = sample_rate;

    /* Attach XDP via BPF link (auto-detach on crash/SIGKILL, kernel 5.9+) */
    int prog_fd = bpf_program__fd(skel->progs.flowlog_xdp);
    LIBBPF_OPTS(bpf_link_create_opts, link_opts, .flags = xdp_flags);
    int xdp_link_fd = bpf_link_create(prog_fd, ifindex, BPF_XDP, &link_opts);
    if (xdp_link_fd < 0) {
        fprintf(stderr, "failed to attach XDP to %s%s\n", ifname,
                (xdp_flags == XDP_FLAGS_DRV_MODE)
                    ? " (native mode — driver may not support it)" : "");
        flowlog_xdp_bpf__destroy(skel);
        return 1;
    }

    if (dyn.enabled) {
        fprintf(stderr, "flowlog: attached to %s (%s%s), exporting to %s "
                "(timeout=%ds, sample=auto:%u:%u, dir=%s)\n",
                ifname,
                (xdp_flags == XDP_FLAGS_DRV_MODE) ? "native" : "skb",
                percpu ? ", percpu" : "",
                collector ? collector : "stderr", timeout_sec,
                dyn.min_rate, dyn.max_rate,
                dir_filter == DIR_INGRESS ? "ingress" :
                dir_filter == DIR_EGRESS  ? "egress"  : "both");
    } else {
        fprintf(stderr, "flowlog: attached to %s (%s%s), exporting to %s "
                "(timeout=%ds, sample=1:%u, dir=%s)\n",
                ifname,
                (xdp_flags == XDP_FLAGS_DRV_MODE) ? "native" : "skb",
                percpu ? ", percpu" : "",
                collector ? collector : "stderr", timeout_sec, sample_rate,
                dir_filter == DIR_INGRESS ? "ingress" :
                dir_filter == DIR_EGRESS  ? "egress"  : "both");
    }

    /* Signal handling */
    struct sigaction sa = { .sa_handler = sig_handler };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Send initial templates */
    if (exp_ptr)
        ipfix_send_templates(exp_ptr);

    /* Compute boottime-to-epoch offset (wall_ns - boot_ns) once at startup.
     * BPF uses bpf_ktime_get_boot_ns() (CLOCK_BOOTTIME) which survives
     * system suspend/hibernate, unlike CLOCK_MONOTONIC. */
    struct timespec wall, boot;
    clock_gettime(CLOCK_REALTIME, &wall);
    clock_gettime(CLOCK_BOOTTIME, &boot);
    int64_t mono_to_epoch_ns =
        ((int64_t)wall.tv_sec * 1000000000LL + wall.tv_nsec) -
        ((int64_t)boot.tv_sec * 1000000000LL + boot.tv_nsec);

    int flow_map_fd = bpf_map__fd(skel->maps.flow_map);
    int pkt_cnt_fd = bpf_map__fd(skel->maps.pkt_counter);
    int bloom_outer_fd = bpf_map__fd(skel->maps.bloom_outer);
    uint64_t prev_pkt_total = 0;

    /* Set up ring buffer consumer for timer mode (non-percpu) */
    struct ring_buffer *rb = NULL;
    struct export_ctx ectx = {};
    if (!percpu) {
        int rb_fd = bpf_map__fd(skel->maps.flow_events);
        ectx.cap = 4096;
        ectx.keys = malloc(ectx.cap * sizeof(*ectx.keys));
        ectx.vals = malloc(ectx.cap * sizeof(*ectx.vals));
        ectx.actions = malloc(ectx.cap);
        if (!ectx.keys || !ectx.vals || !ectx.actions) {
            fprintf(stderr, "failed to allocate export buffers\n");
            close(xdp_link_fd);
            flowlog_xdp_bpf__destroy(skel);
            return 1;
        }
        rb = ring_buffer__new(rb_fd, ringbuf_event_cb, &ectx, NULL);
        if (!rb) {
            fprintf(stderr, "failed to create ring buffer consumer\n");
            close(xdp_link_fd);
            flowlog_xdp_bpf__destroy(skel);
            return 1;
        }
    }

    /* Main loop */
    time_t last_periodic = time(NULL);

    while (running) {
        if (rb) {
            /* Timer mode: poll ringbuf for up to 1 second */
            ring_buffer__poll(rb, 1000);
        } else {
            /* Batch mode: sleep for full timeout */
            unsigned remaining = timeout_sec;
            while (running && remaining > 0)
                remaining = sleep(remaining);
        }
        if (!running)
            break;

        /* Export accumulated ringbuf events */
        if (rb)
            export_batch(&ectx, exp_ptr, mono_to_epoch_ns);

        /* Periodic tasks (every timeout_sec) */
        time_t now_t = time(NULL);
        if (now_t - last_periodic >= (time_t)timeout_sec) {
            if (dyn.enabled) {
                uint64_t cur_total = read_pkt_counter(pkt_cnt_fd, num_cpus);
                uint64_t delta = cur_total - prev_pkt_total;
                prev_pkt_total = cur_total;
                update_dynamic_sample(&dyn, delta, timeout_sec,
                                     &skel->data->cfg_sample_rate);
            }

            /* Batch drain mode: flush map */
            if (!rb) {
                flush_flows(flow_map_fd, exp_ptr, mono_to_epoch_ns,
                            percpu, num_cpus);
            }

            /* Reset bloom filter in both modes — bloom filters have no
             * delete, so entries accumulate until the filter saturates
             * and every lookup returns "present" (negating the optimization) */
            reset_bloom_filter(bloom_outer_fd);

            last_periodic = now_t;
        }
    }

    /* Shutdown: detach XDP first to stop new packets and timer arming,
     * then drain pending events before destroying maps. */
    fprintf(stderr, "shutting down, flushing remaining flows...\n");
    close(xdp_link_fd);

    if (rb) {
        /* Brief wait for in-flight BPF timers to push final events */
        usleep(100000); /* 100 ms */
        /* Drain ringbuf events (including any pushed during the wait) */
        ring_buffer__poll(rb, 0);
        export_batch(&ectx, exp_ptr, mono_to_epoch_ns);
    }
    /* Drain residual map entries (flows whose timers haven't fired yet) */
    flush_flows(flow_map_fd, exp_ptr, mono_to_epoch_ns, percpu, num_cpus);

    /* Cleanup */
    if (rb)
        ring_buffer__free(rb);
    free(ectx.keys);
    free(ectx.vals);
    free(ectx.actions);
    flowlog_xdp_bpf__destroy(skel);
    if (exp_ptr)
        ipfix_close(exp_ptr);
    conntrack_close();

    fprintf(stderr, "flowlog: stopped\n");
    return 0;
}
