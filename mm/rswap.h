/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mm/rswap.h - Remote Swap life cycle
 *
 * rswap is a swap backend that implements the swap_ops interface to
 * store swap pages in an external key-value store.  The KV store key is a
 * SHA-256 hash attached by user space through /proc/sys/vm/rswap/attach.
 * The hash is copied into a per-device table indexed by swap offset at
 * writeout and reused at swapin.  Pages without an attached hash cannot be
 * written to the remote device.
 *
 * == Setup ==
 *
 * 1. Start a KV server.  Both backends shipped with the kernel store one
 *    page object per SHA-256 digest:
 *
 *      HTTP:  kvswap_server -d /path/to/data
 *             write:  POST /v1/folios/<sha256>/write   (body = page data)
 *             read:   GET  /v1/folios/<sha256>/read
 *
 *      Redis: any Redis compatible server
 *             write:  SET <sha256> <page data>
 *             read:   GET <sha256>
 *
 * 2. Create an rswap device (via xswap sysfs):
 *      echo rswap [prio] > /sys/kernel/mm/xswap/create
 *
 * The backend is chosen at boot, before any device exists:
 *
 *      rswap.backend=http|redis	rswap.host=	rswap.port=
 *      rswap.redis_user=	rswap.redis_password=	rswap.redis_db=
 *      rswap.send_timeout_ms=	rswap.recv_timeout_ms=
 *
 * See mm/rswap_backend.h for the backend interface.
 */

#ifdef CONFIG_RSWAP

#include <linux/types.h>
#include <linux/swap.h>

#include "swap.h"

#define RSWAP_HASH_LEN 48

struct rswap_hash {
	char data[RSWAP_HASH_LEN];
};

struct rswap_hash_table {
	struct rswap_hash *hashes[SWAPFILE_CLUSTER];
};

/* ---------- Life-cycle helpers (called from swapfile.c) ---------- */

int  rswap_enable(struct swap_info_struct *si);
void rswap_disable(struct swap_info_struct *si);
void rswap_swapoff(struct swap_info_struct *si);
void rswap_hash_invalidate(struct swap_info_struct *si, unsigned long offset,
			   unsigned int nr_entries);

/* debugfs */
void rswap_debugfs_add(struct swap_info_struct *si);
void rswap_debugfs_del(struct swap_info_struct *si);

/* hash related */
void rswap_attach_hash(swp_entry_t entry, unsigned long addr,
		struct vm_area_struct *vma);

void rswap_attach_hash_shmem(struct page *page, unsigned long addr,
		struct vm_area_struct *vma);

bool rswap_should_alloc_hash(struct vm_area_struct *vma, struct page *page);
void rswap_alloc_hash_slot(struct page *page);

static inline bool rswap_vma_needs_hash(struct vm_area_struct *vma)
{
	return vma->vm_flags & VM_HASHED;
}

#else /* !CONFIG_RSWAP */

static inline int  rswap_enable(struct swap_info_struct *si) { return -EOPNOTSUPP; }
static inline void rswap_disable(struct swap_info_struct *si) { }
static inline void rswap_swapoff(struct swap_info_struct *si) { }
static inline void rswap_hash_invalidate(struct swap_info_struct *si,
					 unsigned long offset,
					 unsigned int nr_entries) { }
static inline void rswap_debugfs_add(struct swap_info_struct *si) { }
static inline void rswap_debugfs_del(struct swap_info_struct *si) { }

static inline bool rswap_should_alloc_hash(struct vm_area_struct *vma,
		struct page *page)
{
	return false;
}

static inline bool rswap_vma_is_hashed(struct vm_area_struct *vma)
{
	return false;
}

#endif /* CONFIG_RSWAP */
