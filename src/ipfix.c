// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ipfix.c — IPFIX message encoding and UDP export (RFC 7011 + RFC 5103 biflow).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include "ipfix.h"

/* --- Buffer helpers --- */

static inline void put_u8(uint8_t **p, uint8_t v)
{
    **p = v;
    (*p)++;
}

static inline void put_u16(uint8_t **p, uint16_t v)
{
    v = htons(v);
    memcpy(*p, &v, 2);
    *p += 2;
}

static inline void put_u32(uint8_t **p, uint32_t v)
{
    v = htonl(v);
    memcpy(*p, &v, 4);
    *p += 4;
}

static inline void put_u64(uint8_t **p, uint64_t v)
{
    uint32_t hi = htonl((uint32_t)(v >> 32));
    uint32_t lo = htonl((uint32_t)v);
    memcpy(*p, &hi, 4);
    memcpy(*p + 4, &lo, 4);
    *p += 8;
}

static inline void put_bytes(uint8_t **p, const void *src, int len)
{
    memcpy(*p, src, len);
    *p += len;
}

/* Write a standard (non-enterprise) field specifier */
static inline void put_field(uint8_t **p, uint16_t ie_id, uint16_t length)
{
    put_u16(p, ie_id);
    put_u16(p, length);
}

/* Write an enterprise field specifier (for reverse IEs, PEN 29305) */
static inline void put_field_ent(uint8_t **p, uint16_t ie_id, uint16_t length,
                                  uint32_t pen)
{
    put_u16(p, ie_id | 0x8000); /* enterprise bit */
    put_u16(p, length);
    put_u32(p, pen);
}

/* --- Template building --- */

/*
 * IPv4 biflow template (Template ID 256):
 *   Forward: srcIPv4(4), dstIPv4(4), srcPort(2), dstPort(2), proto(1),
 *            packetDelta(8), octetDelta(8), flowStartMs(8), flowEndMs(8),
 *            tcpControlBits(2), firewallEvent(1)
 *   Reverse (PEN 29305): packetDelta(8), octetDelta(8), tcpControlBits(2)
 *   biflowDirection(1)
 *
 * Field count: 15
 */
#define TPL_V4_FIELD_COUNT 15

/*
 * IPv6 biflow template (Template ID 257): same but srcIPv6(16), dstIPv6(16)
 * Field count: 15
 */
#define TPL_V6_FIELD_COUNT 15

/* Size of template record (header + fields).
 * Standard field = 4 bytes, enterprise field = 8 bytes.
 * Template record header = 4 bytes (template ID + field count).
 * Standard fields: 12 × 4 = 48, enterprise fields: 3 × 8 = 24.
 * Total per template record = 4 + 48 + 24 = 76.
 */
#define TPL_RECORD_SIZE 76

static int write_template_record(uint8_t **p, uint16_t tpl_id,
                                  uint16_t src_ip_ie, uint16_t dst_ip_ie,
                                  uint16_t addr_len)
{
    uint8_t *start = *p;

    /* Template record header */
    put_u16(p, tpl_id);
    put_u16(p, tpl_id == IPFIX_TPL_ID_V4 ? TPL_V4_FIELD_COUNT : TPL_V6_FIELD_COUNT);

    /* Forward IEs */
    put_field(p, src_ip_ie, addr_len);
    put_field(p, dst_ip_ie, addr_len);
    put_field(p, IE_SRC_TRANSPORT_PORT, 2);
    put_field(p, IE_DST_TRANSPORT_PORT, 2);
    put_field(p, IE_PROTOCOL_IDENTIFIER, 1);
    put_field(p, IE_PACKET_DELTA_COUNT, 8);
    put_field(p, IE_OCTET_DELTA_COUNT, 8);
    put_field(p, IE_FLOW_START_MS, 8);
    put_field(p, IE_FLOW_END_MS, 8);
    put_field(p, IE_TCP_CONTROL_BITS, 2);
    put_field(p, IE_FIREWALL_EVENT, 1);

    /* Reverse IEs (PEN 29305) */
    put_field_ent(p, IE_PACKET_DELTA_COUNT, 8, IPFIX_PEN_REVERSE);
    put_field_ent(p, IE_OCTET_DELTA_COUNT, 8, IPFIX_PEN_REVERSE);
    put_field_ent(p, IE_TCP_CONTROL_BITS, 2, IPFIX_PEN_REVERSE);

    /* biflowDirection */
    put_field(p, IE_BIFLOW_DIRECTION, 1);

    return (int)(*p - start);
}

/* --- Public API --- */

int ipfix_init(struct ipfix_exporter *exp, const char *collector_spec,
               uint32_t obs_domain_id)
{
    memset(exp, 0, sizeof(*exp));
    exp->obs_domain_id = obs_domain_id;
    exp->seq_number = 0;
    exp->last_template_time = 0;

    /* Parse "ip:port" */
    char buf[256];
    strncpy(buf, collector_spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *colon = strrchr(buf, ':');
    if (!colon) {
        fprintf(stderr, "ipfix: invalid collector spec '%s' (need ip:port)\n",
                collector_spec);
        return -1;
    }
    *colon = '\0';
    const char *host = buf;
    const char *port = colon + 1;

    /* Strip brackets from IPv6 addresses: [::1]:port -> ::1 */
    size_t host_len = strlen(host);
    if (host_len >= 2 && host[0] == '[' && host[host_len - 1] == ']') {
        buf[host_len - 1] = '\0';
        host = buf + 1;
    }

    struct addrinfo hints = { .ai_socktype = SOCK_DGRAM };
    struct addrinfo *res;
    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "ipfix: getaddrinfo: %s\n", gai_strerror(rc));
        return -1;
    }

    exp->sockfd = socket(res->ai_family, SOCK_DGRAM, 0);
    if (exp->sockfd < 0) {
        perror("ipfix: socket");
        freeaddrinfo(res);
        return -1;
    }

    memcpy(&exp->collector, res->ai_addr, res->ai_addrlen);
    exp->collector_len = res->ai_addrlen;
    freeaddrinfo(res);

    return 0;
}

/* Write IPFIX message header at the start of buf */
static void write_msg_hdr(uint8_t *buf, uint16_t length,
                           struct ipfix_exporter *exp)
{
    uint8_t *p = buf;
    put_u16(&p, IPFIX_VERSION);
    put_u16(&p, length);
    put_u32(&p, (uint32_t)time(NULL));
    put_u32(&p, exp->seq_number);
    put_u32(&p, exp->obs_domain_id);
}

static int send_buf(struct ipfix_exporter *exp, int len, int num_records)
{
    ssize_t sent = sendto(exp->sockfd, exp->buf, len, 0,
                          (struct sockaddr *)&exp->collector,
                          exp->collector_len);
    if (sent < 0) {
        perror("ipfix: sendto");
        return -1;
    }
    /* RFC 7011 §3.1: sequence number counts cumulative data records */
    exp->seq_number += num_records;
    return 0;
}

int ipfix_send_templates(struct ipfix_exporter *exp)
{
    uint8_t *p = exp->buf;
    uint8_t *msg_start = p;

    /* Skip message header (16 bytes) — fill later */
    p += 16;

    /* Template Set header */
    uint8_t *set_start = p;
    put_u16(&p, IPFIX_TEMPLATE_SET_ID);
    put_u16(&p, 0); /* length placeholder */

    /* IPv4 template record */
    write_template_record(&p, IPFIX_TPL_ID_V4, IE_SRC_IPV4_ADDR,
                          IE_DST_IPV4_ADDR, 4);

    /* IPv6 template record */
    write_template_record(&p, IPFIX_TPL_ID_V6, IE_SRC_IPV6_ADDR,
                          IE_DST_IPV6_ADDR, 16);

    /* Fix up set length */
    uint16_t set_len = (uint16_t)(p - set_start);
    uint8_t *sl = set_start + 2;
    put_u16(&sl, set_len);

    /* Fix up message header */
    uint16_t msg_len = (uint16_t)(p - msg_start);
    write_msg_hdr(msg_start, msg_len, exp);

    exp->last_template_time = time(NULL);
    return send_buf(exp, msg_len, 0);
}

/*
 * Convert ktime_ns (monotonic) to epoch milliseconds.
 * mono_to_epoch_ns = wall_ns - mono_ns, computed once at startup.
 */
uint64_t ktime_to_epoch_ms(uint64_t ktime_ns, int64_t mono_to_epoch_ns)
{
    return (uint64_t)((int64_t)ktime_ns + mono_to_epoch_ns) / 1000000ULL;
}

/* Size of one IPv4 data record (no set header, no msg header) */
#define DATA_REC_V4_SIZE (4+4+2+2+1+8+8+8+8+2+1+8+8+2+1)  /* = 67 */
/* Size of one IPv6 data record */
#define DATA_REC_V6_SIZE (16+16+2+2+1+8+8+8+8+2+1+8+8+2+1) /* = 91 */

static int write_data_record(uint8_t **p, const struct flow_key *key,
                              const struct flow_value *val, uint8_t action,
                              int64_t mono_to_epoch_ns)
{
    uint8_t *start = *p;

    /* Addresses */
    if (key->family == 2) { /* AF_INET */
        put_bytes(p, &key->init_addr.v4, 4);
        put_bytes(p, &key->resp_addr.v4, 4);
    } else { /* AF_INET6 */
        put_bytes(p, &key->init_addr.v6, 16);
        put_bytes(p, &key->resp_addr.v6, 16);
    }

    /* Ports */
    put_u16(p, ntohs(key->init_port));
    put_u16(p, ntohs(key->resp_port));

    /* Protocol */
    put_u8(p, key->protocol);

    /* Forward counters */
    put_u64(p, val->init_packets);
    put_u64(p, val->init_bytes);

    /* Timestamps */
    put_u64(p, ktime_to_epoch_ms(val->first_seen_ns, mono_to_epoch_ns));
    put_u64(p, ktime_to_epoch_ms(val->last_seen_ns, mono_to_epoch_ns));

    /* Forward TCP flags */
    put_u16(p, val->init_tcp_flags);

    /* Firewall event */
    put_u8(p, action);

    /* Reverse counters (PEN 29305 — already declared in template) */
    put_u64(p, val->resp_packets);
    put_u64(p, val->resp_bytes);

    /* Reverse TCP flags */
    put_u16(p, val->resp_tcp_flags);

    /* biflowDirection = 1 (initiator) */
    put_u8(p, 1);

    return (int)(*p - start);
}

int ipfix_export_flows(struct ipfix_exporter *exp,
                       struct flow_key *keys,
                       struct flow_value *values,
                       uint8_t *actions,
                       int count,
                       int64_t mono_to_epoch_ns)
{
    if (count == 0)
        return 0;

    /* Re-send templates if needed */
    time_t now = time(NULL);
    if (now - exp->last_template_time >= IPFIX_TEMPLATE_INTERVAL)
        ipfix_send_templates(exp);

    int exported = 0;

    /* Group by address family and send in batches */
    for (int af = 2; af <= 10; af += 8) { /* AF_INET=2, AF_INET6=10 */
        uint16_t tpl_id = (af == 2) ? IPFIX_TPL_ID_V4 : IPFIX_TPL_ID_V6;
        int rec_size = (af == 2) ? DATA_REC_V4_SIZE : DATA_REC_V6_SIZE;

        /* Max records per message */
        int max_per_msg = (IPFIX_MAX_MSG_LEN - 16 - 4) / rec_size;
        if (max_per_msg < 1) max_per_msg = 1;

        uint8_t *p = exp->buf;
        uint8_t *msg_start = p;
        p += 16; /* skip msg header */

        /* Data set header */
        uint8_t *set_start = p;
        put_u16(&p, tpl_id);
        put_u16(&p, 0); /* length placeholder */

        int in_msg = 0;

        for (int i = 0; i < count; i++) {
            if (keys[i].family != af)
                continue;

            /* Check if this record fits */
            if (in_msg >= max_per_msg) {
                /* Flush current message */
                uint16_t set_len = (uint16_t)(p - set_start);
                uint8_t *sl = set_start + 2;
                put_u16(&sl, set_len);

                uint16_t msg_len = (uint16_t)(p - msg_start);
                write_msg_hdr(msg_start, msg_len, exp);
                if (send_buf(exp, msg_len, in_msg) < 0)
                    exported -= in_msg;

                /* Start new message */
                p = exp->buf;
                msg_start = p;
                p += 16;
                set_start = p;
                put_u16(&p, tpl_id);
                put_u16(&p, 0);
                in_msg = 0;
            }

            write_data_record(&p, &keys[i], &values[i], actions[i], mono_to_epoch_ns);
            in_msg++;
            exported++;
        }

        /* Flush remaining */
        if (in_msg > 0) {
            uint16_t set_len = (uint16_t)(p - set_start);
            uint8_t *sl = set_start + 2;
            put_u16(&sl, set_len);

            uint16_t msg_len = (uint16_t)(p - msg_start);
            write_msg_hdr(msg_start, msg_len, exp);
            if (send_buf(exp, msg_len, in_msg) < 0)
                exported -= in_msg;
        }
    }

    return exported;
}

void ipfix_close(struct ipfix_exporter *exp)
{
    if (exp->sockfd >= 0) {
        close(exp->sockfd);
        exp->sockfd = -1;
    }
}
