// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * conntrack.c — Best-effort ACCEPT/REJECT determination via conntrack.
 *
 * Uses libnetfilter_conntrack to query the kernel conntrack table.
 * If a matching entry exists → ACCEPT, otherwise → REJECT (best-effort).
 *
 * Limitations:
 * - Only works if nf_conntrack module is loaded.
 * - Short-lived flows may have expired from conntrack before export.
 * - Does not reflect actual firewall rules, only connection tracking state.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include "conntrack.h"

static struct nfct_handle *cth;
static int ct_available;
static int warned;

int conntrack_init(void)
{
    cth = nfct_open(CONNTRACK, 0);
    if (!cth) {
        fprintf(stderr, "conntrack: nfct_open failed: %s "
                "(conntrack will default to ACCEPT)\n", strerror(errno));
        ct_available = 0;
        return 0; /* non-fatal */
    }
    ct_available = 1;
    warned = 0;
    return 0;
}

/* Build a conntrack query object for the given flow direction */
static struct nf_conntrack *build_ct_query(const struct flow_key *key,
                                            int reverse)
{
    struct nf_conntrack *ct = nfct_new();
    if (!ct)
        return NULL;

    uint8_t af = (key->family == 2) ? AF_INET : AF_INET6;
    nfct_set_attr_u8(ct, ATTR_L3PROTO, af);
    nfct_set_attr_u8(ct, ATTR_L4PROTO, key->protocol);

    if (!reverse) {
        if (af == AF_INET) {
            nfct_set_attr_u32(ct, ATTR_IPV4_SRC, key->init_addr.v4);
            nfct_set_attr_u32(ct, ATTR_IPV4_DST, key->resp_addr.v4);
        } else {
            nfct_set_attr(ct, ATTR_IPV6_SRC, &key->init_addr.v6);
            nfct_set_attr(ct, ATTR_IPV6_DST, &key->resp_addr.v6);
        }
        if (key->protocol == 6 || key->protocol == 17) {
            nfct_set_attr_u16(ct, ATTR_PORT_SRC, key->init_port);
            nfct_set_attr_u16(ct, ATTR_PORT_DST, key->resp_port);
        }
    } else {
        if (af == AF_INET) {
            nfct_set_attr_u32(ct, ATTR_IPV4_SRC, key->resp_addr.v4);
            nfct_set_attr_u32(ct, ATTR_IPV4_DST, key->init_addr.v4);
        } else {
            nfct_set_attr(ct, ATTR_IPV6_SRC, &key->resp_addr.v6);
            nfct_set_attr(ct, ATTR_IPV6_DST, &key->init_addr.v6);
        }
        if (key->protocol == 6 || key->protocol == 17) {
            nfct_set_attr_u16(ct, ATTR_PORT_SRC, key->resp_port);
            nfct_set_attr_u16(ct, ATTR_PORT_DST, key->init_port);
        }
    }

    /* ICMP uses type/code instead of ports (same for both directions) */
    if (key->protocol == 1 || key->protocol == 58) {
        nfct_set_attr_u8(ct, ATTR_ICMP_TYPE, ntohs(key->init_port));
        nfct_set_attr_u8(ct, ATTR_ICMP_CODE, ntohs(key->resp_port));
    }

    return ct;
}

uint8_t conntrack_lookup(const struct flow_key *key)
{
    if (!ct_available)
        return FW_EVENT_ACCEPT;

    /* Try forward direction (init=src, resp=dst) */
    struct nf_conntrack *ct = build_ct_query(key, 0);
    if (!ct) {
        if (!warned) {
            fprintf(stderr, "conntrack: nfct_new failed\n");
            warned = 1;
        }
        return FW_EVENT_ACCEPT;
    }

    if (nfct_query(cth, NFCT_Q_GET, ct) == 0) {
        nfct_destroy(ct);
        return FW_EVENT_ACCEPT;
    }
    nfct_destroy(ct);

    /* Try reverse direction (resp=src, init=dst) since the flow key is
     * normalized by IP and may not match conntrack's original direction. */
    if (key->protocol == 6 || key->protocol == 17) {
        ct = build_ct_query(key, 1);
        if (ct) {
            if (nfct_query(cth, NFCT_Q_GET, ct) == 0) {
                nfct_destroy(ct);
                return FW_EVENT_ACCEPT;
            }
            nfct_destroy(ct);
        }
    }

    return FW_EVENT_IGNORE;
}

void conntrack_close(void)
{
    if (cth) {
        nfct_close(cth);
        cth = NULL;
    }
    ct_available = 0;
}
