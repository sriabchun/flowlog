/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IPFIX_H
#define IPFIX_H

#include <stdint.h>
#include <netinet/in.h>
#include "flow.h"

/* IPFIX constants */
#define IPFIX_VERSION           10
#define IPFIX_TEMPLATE_SET_ID   2
#define IPFIX_TPL_ID_V4         256
#define IPFIX_TPL_ID_V6         257
#define IPFIX_MAX_MSG_LEN       1400   /* MTU-safe */
#define IPFIX_TEMPLATE_INTERVAL 300    /* re-send templates every 5 min */

/* RFC 5103 reverse IE PEN */
#define IPFIX_PEN_REVERSE       29305

/* IANA IPFIX IE IDs */
#define IE_OCTET_DELTA_COUNT            1
#define IE_PACKET_DELTA_COUNT           2
#define IE_PROTOCOL_IDENTIFIER          4
#define IE_TCP_CONTROL_BITS             6
#define IE_SRC_TRANSPORT_PORT           7
#define IE_SRC_IPV4_ADDR                8
#define IE_DST_TRANSPORT_PORT           11
#define IE_DST_IPV4_ADDR                12
#define IE_SRC_IPV6_ADDR                27
#define IE_DST_IPV6_ADDR                28
#define IE_FLOW_START_MS                152
#define IE_FLOW_END_MS                  153
#define IE_FIREWALL_EVENT               233
#define IE_BIFLOW_DIRECTION             239

/* IPFIX message header (RFC 7011 §3.1) */
struct __attribute__((packed)) ipfix_hdr {
    uint16_t version;
    uint16_t length;
    uint32_t export_time;
    uint32_t seq_number;
    uint32_t obs_domain_id;
};

/* IPFIX set header */
struct __attribute__((packed)) ipfix_set_hdr {
    uint16_t set_id;
    uint16_t length;
};

/* IPFIX template field specifier */
struct __attribute__((packed)) ipfix_field_spec {
    uint16_t ie_id;         /* bit 15 = enterprise bit */
    uint16_t length;
    uint32_t enterprise_id; /* only present if enterprise bit set */
};

/* IPFIX exporter state */
struct ipfix_exporter {
    int         sockfd;
    struct sockaddr_storage collector;
    socklen_t   collector_len;
    uint32_t    obs_domain_id;
    uint32_t    seq_number;
    time_t      last_template_time;
    uint8_t     buf[IPFIX_MAX_MSG_LEN];
};

/* Initialize exporter: create UDP socket, set collector address */
int ipfix_init(struct ipfix_exporter *exp, const char *collector_spec,
               uint32_t obs_domain_id);

/* Send template sets (IPv4 + IPv6) */
int ipfix_send_templates(struct ipfix_exporter *exp);

/* Export a batch of flows. Returns number of flows exported. */
int ipfix_export_flows(struct ipfix_exporter *exp,
                       struct flow_key *keys,
                       struct flow_value *values,
                       uint8_t *actions,
                       int count,
                       int64_t mono_to_epoch_ns);

/* Convert ktime_ns (monotonic) to epoch milliseconds.
 * mono_to_epoch_ns = wall_ns - mono_ns, computed once at startup. */
uint64_t ktime_to_epoch_ms(uint64_t ktime_ns, int64_t mono_to_epoch_ns);

/* Close socket */
void ipfix_close(struct ipfix_exporter *exp);

#endif /* IPFIX_H */
