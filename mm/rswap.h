/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mm/rswap.h - Remote Swap life cycle
 *
 * rswap is a swap backend that implements the swap_ops interface to
 * store swap pages in an external key-value store.  The KV store key is a
 * SHA-256 hash supplied by user space; the kernel never derives it from the
 * page contents or from the swap entry.
 *
 * The hash is resolved while the folio is still mapped, at unmap time, and
 * stored in the swap cluster that backs the folio.  Swapin reads the same
 * table, so the key never depends on the page still existing.  Pages whose
 * hash was not resolved cannot be written to the remote device.
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
 * The backend is chosen at boot, before any device exists, and cannot be
 * switched afterwards: a live device keeps the store it was written with.
 * The two timeouts can also be written at runtime through
 * /sys/module/rswap/parameters/.
 *
 *      rswap.backend=http|redis	rswap.host=	rswap.port=
 *      rswap.redis_user=	rswap.redis_password=	rswap.redis_db=
 *      rswap.send_timeout_ms=	rswap.recv_timeout_ms=
 *
 * See mm/rswap_backend.h for the backend interface.
 */

#ifndef _MM_RSWAP_H
#define _MM_RSWAP_H

#include <linux/types.h>
#include <linux/swap.h>

#include "swap.h"

struct vm_area_struct;

#ifdef CONFIG_RSWAP

#define RSWAP_HASH_LEN 48

/*
 * One digest slot.  @data holds the digest user space supplied for the base
 * page using this swap offset; @valid says that the bytes may be read.
 *
 * The slot object is published once, by rswap_slot_get(), and then belongs to
 * its cluster, so the pointer alone only means "this offset has a slot".  A
 * slot is reserved when a folio enters the swap cache, long before the digest
 * for it is known, and it outlives the swap entry it describes, so validity
 * is tracked separately: a reserved but unresolved slot, and a slot whose
 * swap entry was released, report "no digest" instead of a zero digest.
 *
 * Writers copy @data and then publish with smp_store_release(&slot->valid, 1);
 * readers do smp_load_acquire(&slot->valid) before touching @data.
 */
struct rswap_hash {
	char data[RSWAP_HASH_LEN];
	u8 valid;
};

/*
 * Context of the digest program the kernel runs for a base page.  The program
 * fills @hash; BPF_PROG_TYPE_SYSCALL programs may write to their context.
 */
struct rswap_hash_ctx {
	u64	vaddr;
	u8	hash[RSWAP_HASH_LEN];
};

/*
 * One table per swap cluster, allocated when the cluster is first used and
 * freed with it.  Slot i describes swap offset
 * cluster_start + i; a NULL slot means "no slot reserved", and a slot whose
 * valid flag is clear means "no hash resolved".
 */
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

/* ---------- Hash slots (called from swapfile.c) ---------- */

/* Allocate the slots of a folio that just entered the swap cache. */
void rswap_prepare_hashes(struct folio *folio, gfp_t gfp);
/* Free the table of a cluster that is being released. */
void rswap_hash_table_free(struct swap_cluster_info *ci);

/* ---------- Per-VMA digest program ---------- */

int rswap_attach_prog(unsigned long vaddr, int prog_fd);
void rswap_vma_dup(struct vm_area_struct *vma);
void rswap_vma_free(struct vm_area_struct *vma);

/* ---------- Hash attach (called from rmap.c) ---------- */

/* Anonymous folio: the swap entry already exists, store the hash in it. */
void rswap_attach_hash(swp_entry_t entry, unsigned long addr,
		struct vm_area_struct *vma);

/* Shmem folio: no swap entry yet, stage the hash in the inode. */
void rswap_attach_hash_shmem(struct folio *folio, unsigned long addr,
		struct vm_area_struct *vma);

/* ---------- Shmem staging area (called from shmem.c) ---------- */

/* Move the staged hashes of @folio into its swap cluster. */
void rswap_shmem_move_hashes(struct inode *inode, struct folio *folio);
/* Drop the staged hashes of an index range. */
void rswap_shmem_drop_hashes(struct inode *inode, pgoff_t start, pgoff_t end);
/* Drop every staged hash of an inode that is going away. */
void rswap_shmem_free_hashes(struct inode *inode);

static inline bool rswap_vma_needs_hash(struct vm_area_struct *vma)
{
	return vma->vm_flags & VM_HASHED;
}

#else /* !CONFIG_RSWAP */

static inline int rswap_enable(struct swap_info_struct *si)
{
	return -EOPNOTSUPP;
}
static inline void rswap_disable(struct swap_info_struct *si)
{
}
static inline void rswap_swapoff(struct swap_info_struct *si)
{
}
static inline void rswap_hash_invalidate(struct swap_info_struct *si,
					 unsigned long offset,
					 unsigned int nr_entries)
{
}
static inline void rswap_debugfs_add(struct swap_info_struct *si)
{
}
static inline void rswap_debugfs_del(struct swap_info_struct *si)
{
}

static inline void rswap_prepare_hashes(struct folio *folio, gfp_t gfp)
{
}
static inline int rswap_attach_prog(unsigned long vaddr, int prog_fd)
{
	return -EOPNOTSUPP;
}
static inline void rswap_hash_table_free(struct swap_cluster_info *ci)
{
}
static inline void rswap_attach_hash(swp_entry_t entry, unsigned long addr,
				     struct vm_area_struct *vma)
{
}
static inline void rswap_attach_hash_shmem(struct folio *folio,
					   unsigned long addr,
					   struct vm_area_struct *vma)
{
}
static inline void rswap_shmem_move_hashes(struct inode *inode,
					   struct folio *folio)
{
}
static inline void rswap_shmem_drop_hashes(struct inode *inode, pgoff_t start,
					   pgoff_t end)
{
}
static inline void rswap_shmem_free_hashes(struct inode *inode)
{
}

static inline bool rswap_vma_needs_hash(struct vm_area_struct *vma)
{
	return false;
}

#endif /* CONFIG_RSWAP */

#endif /* _MM_RSWAP_H */
