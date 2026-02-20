/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CONNTRACK_H
#define CONNTRACK_H

#include "flow.h"

/* firewallEvent values */
#define FW_EVENT_IGNORE  0  /* no match / reject */
#define FW_EVENT_CREATED 1
#define FW_EVENT_ACCEPT  2

/* Initialize conntrack subsystem. Returns 0 on success, -1 on failure. */
int conntrack_init(void);

/*
 * Lookup a flow in conntrack.
 * Returns FW_EVENT_ACCEPT if found, FW_EVENT_IGNORE if not found.
 */
uint8_t conntrack_lookup(const struct flow_key *key);

/* Cleanup conntrack resources */
void conntrack_close(void);

#endif /* CONNTRACK_H */
