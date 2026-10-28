/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mm/rswap.h - Remote Swap via HTTP KV Store
 *
 * rswap is a swap backend that implements the swap_ops interface to
 * store swap pages in an external key-value store reachable over HTTP.
 * The KV store key is the SHA-256 hash of the swap entry value.
 *
 * == Setup ==
 *
 * 1. Start the KV server:
 *      kvswap_server -d /path/to/data
 *
 * 2. Create an rswap device (via xswap sysfs):
 *      echo rswap [prio] > /sys/kernel/mm/xswap/create
 *
 * The kernel now routes all swap I/O on this device through HTTP
 * requests to the KV server at 127.0.0.1:6789.
 *
 *   write:  POST /v1/folios/<sha256>/write   (body = folio data)
 *   read:   GET  /v1/folios/<sha256>/read
 *
 * The KV server stores each page in a file named by the SHA-256 hex
 * string.
 */

#ifdef CONFIG_RSWAP

#include <linux/types.h>

/* ---------- Life-cycle helpers (called from swapfile.c) ---------- */

int  rswap_enable(struct swap_info_struct *si);
void rswap_disable(struct swap_info_struct *si);
void rswap_swapoff(struct swap_info_struct *si);

/* debugfs */
void rswap_debugfs_add(struct swap_info_struct *si);
void rswap_debugfs_del(struct swap_info_struct *si);

#else /* !CONFIG_RSWAP */

static inline int  rswap_enable(struct swap_info_struct *si) { return -EOPNOTSUPP; }
static inline void rswap_disable(struct swap_info_struct *si) { }
static inline void rswap_swapoff(struct swap_info_struct *si) { }
static inline void rswap_debugfs_add(struct swap_info_struct *si) { }
static inline void rswap_debugfs_del(struct swap_info_struct *si) { }

#endif /* CONFIG_RSWAP */
