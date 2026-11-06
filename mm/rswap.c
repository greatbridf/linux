// SPDX-License-Identifier: GPL-2.0
/*
 * mm/rswap.c - Remote Swap core
 *
 * rswap implements the swap_ops interface to perform swap I/O through an
 * external key-value store.  The KV store key is a SHA-256 digest, encoded as
 * a hex string.  Which protocol carries the page to that store is decided by
 * a pluggable backend (see mm/rswap_backend.h); this file owns the keys, the
 * page_ext digests, the per-device table and the swap_ops wiring.
 *
 * == Keys ==
 *
 * The digest is supplied by user space, which knows what a page holds.  The
 * kernel never hashes page contents and never derives a key from a swap
 * entry; it only asks user space for the digest attached to an address.  The
 * digest is resolved while the folio is still mapped, at unmap time, and
 * stored in the swap cluster that backs the folio.  Swapin uses that stored
 * digest as the KV key, so the key does not depend on the page remaining in
 * the swap cache.  Pages without a resolved digest cannot be written to
 * rswap.
 *
 * == Data flow ==
 *
 * swap-out (reclaim):
 *   swap_writeout() -> swap_add_folio() -> swap_write_submit()
 *   -> rswap_submit_write() -> backend->store(<sha256>, page)
 *
 * swap-in (page fault):
 *   swap_read_folio() -> swap_add_folio() -> swap_read_submit()
 *   -> rswap_submit_read()  -> backend->load(<sha256>, page)
 *
 * Backends shipped with rswap:
 *
 *   http  (mm/rswap_http.c)   POST/GET /v1/folios/<sha256>/{write,read}
 *   redis (mm/rswap_redis.c)  RESP SET/GET <sha256>
 *
 * The backend is picked with the rswap.backend parameter (or the Kconfig
 * default).  Both store one page object per SHA-256 hex key.
 */

#define pr_fmt(fmt) "rswap: " fmt

#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/swap_ops.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <crypto/sha2.h>
#include <linux/hex.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/page_ext.h>
#include <linux/sysctl.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/shmem_fs.h>
#include <linux/xarray.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/mman.h>

#include "swap.h"
#include "rswap.h"
#include "rswap_backend.h"

/* ---------- Configuration ---------- */

#define RSWAP_HASH_HEXLEN	(2 * RSWAP_HASH_LEN)
/* Legacy /proc/sys/vm/rswap/attach digests are still SHA-256. */
#define RSWAP_SHA256_HEXLEN	64

static_assert(RSWAP_HASH_HEXLEN + 1 == RSWAP_KV_KEY_LEN);

/*
 * Backend selection.  These are boot parameters: switching a live swap device
 * to a different store would strand every page already written to the old
 * one, so none of them is writable at runtime.
 */
static char rswap_backend_name[16] = "http";
module_param_string(backend, rswap_backend_name, sizeof(rswap_backend_name),
		    0444);
MODULE_PARM_DESC(backend, "KV backend to use: http or redis");

static char rswap_kv_host[RSWAP_KV_HOST_LEN];
module_param_string(host, rswap_kv_host, sizeof(rswap_kv_host), 0444);
MODULE_PARM_DESC(host,
		 "KV endpoint address; empty selects the backend default");

static unsigned short rswap_kv_port;
module_param_named(port, rswap_kv_port, ushort, 0444);
MODULE_PARM_DESC(port, "KV endpoint port; 0 selects the backend default");

static char rswap_kv_user[RSWAP_KV_HOST_LEN];
module_param_string(redis_user, rswap_kv_user, sizeof(rswap_kv_user), 0444);
MODULE_PARM_DESC(redis_user, "Redis ACL user; empty uses the default user");

static char rswap_kv_password[128];
module_param_string(redis_password, rswap_kv_password,
		    sizeof(rswap_kv_password), 0);
MODULE_PARM_DESC(redis_password, "Redis AUTH secret; empty sends no AUTH");

static unsigned int rswap_kv_db;
module_param_named(redis_db, rswap_kv_db, uint, 0444);
MODULE_PARM_DESC(redis_db, "Redis database number");

static unsigned int rswap_kv_send_timeout_ms;
module_param_named(send_timeout_ms, rswap_kv_send_timeout_ms, uint, 0444);
MODULE_PARM_DESC(send_timeout_ms,
		 "Send/connect timeout; 0 selects the backend default");

static unsigned int rswap_kv_recv_timeout_ms;
module_param_named(recv_timeout_ms, rswap_kv_recv_timeout_ms, uint, 0444);
MODULE_PARM_DESC(recv_timeout_ms,
		 "Receive timeout; 0 selects the backend default");

/* ---------- KV backend selection ---------- */

/* Selected backend and its resolved configuration, valid after init. */
static const struct rswap_backend *rswap_backend;
static struct rswap_kv_config rswap_backend_cfg;
static char rswap_backend_endpoint[RSWAP_KV_HOST_LEN + 8];

static void __init rswap_debugfs_init(void);

static const __initconst struct rswap_backend *rswap_backends[] = {
#ifdef CONFIG_RSWAP_KV_HTTP
	&rswap_http_backend,
#endif
#ifdef CONFIG_RSWAP_KV_REDIS
	&rswap_redis_backend,
#endif
};

/*
 * A device without a backend cannot move a single page: rswap_backends[]
 * would be empty, the late init would fail and every device create would be
 * rejected with -ENODEV.  Catch that at build time instead.
 */
#if !IS_ENABLED(CONFIG_RSWAP_KV_HTTP) && !IS_ENABLED(CONFIG_RSWAP_KV_REDIS)
#error "RSWAP needs at least one KV backend: enable RSWAP_KV_HTTP or RSWAP_KV_REDIS"
#endif

static int __init rswap_backend_setup(void)
{
	const struct rswap_backend *backend = NULL;
	struct rswap_kv_config *cfg = &rswap_backend_cfg;
	size_t i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(rswap_backends); i++) {
		if (!strcmp(rswap_backend_name, rswap_backends[i]->name)) {
			backend = rswap_backends[i];
			break;
		}
	}
	if (!backend) {
		pr_err("unknown or disabled KV backend \"%s\"\n",
		       rswap_backend_name);
		return -EINVAL;
	}

	/* Fill in every default so backends only ever see final values. */
	cfg->host = rswap_kv_host[0] ? rswap_kv_host : backend->default_host;
	cfg->port = rswap_kv_port ?: backend->default_port;
	cfg->user = rswap_kv_user[0] ? rswap_kv_user : NULL;
	cfg->password = rswap_kv_password[0] ? rswap_kv_password : NULL;
	cfg->db = rswap_kv_db;
	cfg->send_timeout_ms = rswap_kv_send_timeout_ms ?:
		backend->default_send_timeout_ms;
	cfg->recv_timeout_ms = rswap_kv_recv_timeout_ms ?:
		backend->default_recv_timeout_ms;

	if (backend->init) {
		ret = backend->init(cfg);
		if (ret) {
			pr_err("%s: backend setup failed: %d\n", backend->name,
			       ret);
			return ret;
		}
	}

	rswap_backend = backend;
	snprintf(rswap_backend_endpoint, sizeof(rswap_backend_endpoint), "%s:%u",
		 cfg->host, cfg->port);
	rswap_debugfs_init();
	pr_info("using %s KV backend at %s (%s)\n", backend->name,
		rswap_backend_endpoint, backend->description);
	return 0;
}

/*
 * Before any device can be created from user space, but late enough that the
 * parameter overrides have been parsed.
 */
late_initcall(rswap_backend_setup);

/* Move @nr base page images to the KV store. */
static int rswap_kv_store(struct rswap_kv_page *pages, unsigned int nr,
			  size_t len)
{
	return rswap_backend->store(pages, nr, len);
}

/* Move @nr base page images from the KV store. */
static int rswap_kv_load(struct rswap_kv_page *pages, unsigned int nr,
			 size_t len)
{
	return rswap_backend->load(pages, nr, len);
}

/* ---------- Statistics ---------- */

/*
 * Per-device I/O counters, reachable from struct swap_info_struct.  They are
 * lock-free: swap I/O runs on many CPUs at once and stats must never
 * serialize it, and a lost update on a debugfs read is harmless.
 *
 * Every batch counts into the block of its device, so the block has to
 * outlive the device: @refs is held once by the device and once by every
 * batch that captured the pointer, which is what keeps a batch queued while
 * the device is torn down from writing into freed memory.
 */
struct rswap_stats {
	refcount_t	refs;
	atomic64_t	pages_written;
	atomic64_t	pages_read;
	atomic64_t	errors_written;
	atomic64_t	errors_read;
	atomic64_t	no_digest;	/* writeout, no digest attached */
	atomic64_t	no_entry;	/* swapin, no digest stored */
};

/* Backend-wide counters: the sum over all devices plus round trip timing. */
static struct rswap_stats rswap_total;

struct rswap_io_stats {
	atomic64_t	batches;
	atomic64_t	ns;
	atomic64_t	max_ns;
};

static struct rswap_io_stats rswap_write_io;
static struct rswap_io_stats rswap_read_io;

/* Take a reference on a device's counter block; @stats may be NULL. */
static struct rswap_stats *rswap_stats_get(struct rswap_stats *stats)
{
	if (stats)
		refcount_inc(&stats->refs);
	return stats;
}

/* Drop a reference, freeing the block once nothing counts into it any more. */
static void rswap_stats_put(struct rswap_stats *stats)
{
	if (stats && refcount_dec_and_test(&stats->refs))
		kfree(stats);
}

static void rswap_stats_max(atomic64_t *max, s64 value)
{
	s64 old = atomic64_read(max);

	while (old < value) {
		s64 prev = atomic64_cmpxchg(max, old, value);

		if (prev == old)
			return;
		old = prev;
	}
}

static void rswap_stats_pages(struct rswap_stats *stats, int rw,
			      unsigned int pages)
{
	if (!stats || !pages)
		return;
	if (rw == WRITE)
		atomic64_add(pages, &stats->pages_written);
	else
		atomic64_add(pages, &stats->pages_read);
}

static void rswap_stats_errors(struct rswap_stats *stats, int rw,
			       unsigned int pages)
{
	if (!stats || !pages)
		return;
	if (rw == WRITE)
		atomic64_add(pages, &stats->errors_written);
	else
		atomic64_add(pages, &stats->errors_read);
}

/*
 * Pages of a request that never reached the backend: no digest on writeout,
 * none stored on swapin.  Both are expected for pages user space never
 * attached.  @pages is the number of pages that stayed where they were; only
 * the page that was found without a digest is counted as such, because the
 * kind of the others is unknown.
 */
static void rswap_stats_key_failure(struct rswap_stats *stats, int rw, int err,
				    unsigned int pages)
{
	if (!stats)
		return;
	if (rw == WRITE && err == -ENODATA)
		atomic64_inc(&stats->no_digest);
	else if (rw == READ && err == -ENOENT)
		atomic64_inc(&stats->no_entry);
	rswap_stats_errors(stats, rw, pages);
}

static void rswap_stats_io(struct rswap_io_stats *io, s64 ns)
{
	atomic64_inc(&io->batches);
	atomic64_add(ns, &io->ns);
	rswap_stats_max(&io->max_ns, ns);
}

/* ---------- Per-page digests (page_ext) ---------- */

/*
 * User space attaches a SHA-256 digest to a base page.  Storing it in
 * page_ext means it follows the folio around: the same page that is
 * written out is the one kept in the swap cache and read back in, so the
 * digest survives the round trip without any side table.
 */
struct rswap_page_ext {
	u8	hash[SHA256_DIGEST_SIZE];
	bool	valid;
};

static bool need_rswap_page_ext(void)
{
	return true;
}

struct page_ext_operations rswap_page_ext_ops = {
	.size	= sizeof(struct rswap_page_ext),
	.need	= need_rswap_page_ext,
};

static DEFINE_SPINLOCK(rswap_hash_lock);

/* Copy the attached digest out of @page.  False if none is attached. */
static bool rswap_page_get_hash(struct page *page, u8 *hash)
{
	struct page_ext *page_ext = page_ext_get(page);
	struct rswap_page_ext *re;
	bool attached = false;
	unsigned long flags;

	if (!page_ext)
		return false;

	re = page_ext_data(page_ext, &rswap_page_ext_ops);
	spin_lock_irqsave(&rswap_hash_lock, flags);
	if (re->valid) {
		memcpy(hash, re->hash, SHA256_DIGEST_SIZE);
		attached = true;
	}
	spin_unlock_irqrestore(&rswap_hash_lock, flags);
	page_ext_put(page_ext);
	return attached;
}

/* Attach @hash to @page. */
static int rswap_page_set_hash(struct page *page, const u8 *hash)
{
	struct page_ext *page_ext = page_ext_get(page);
	struct rswap_page_ext *re;
	unsigned long flags;

	if (!page_ext)
		return -ENODEV;

	re = page_ext_data(page_ext, &rswap_page_ext_ops);
	spin_lock_irqsave(&rswap_hash_lock, flags);
	memcpy(re->hash, hash, SHA256_DIGEST_SIZE);
	WRITE_ONCE(re->valid, true);
	spin_unlock_irqrestore(&rswap_hash_lock, flags);
	page_ext_put(page_ext);
	return 0;
}

/*
 * page_ext is associated with the physical page, so stale digests must be
 * cleared when the page returns to the allocator and copied on migration.
 */
void rswap_page_ext_reset(struct page *page, unsigned int order)
{
	struct page_ext_iter iter;
	struct page_ext *page_ext;
	struct rswap_page_ext *re;
	unsigned long flags;

	rcu_read_lock();
	for_each_page_ext(page, 1UL << order, page_ext, iter) {
		re = page_ext_data(page_ext, &rswap_page_ext_ops);
		if (!READ_ONCE(re->valid))
			continue;
		spin_lock_irqsave(&rswap_hash_lock, flags);
		WRITE_ONCE(re->valid, false);
		spin_unlock_irqrestore(&rswap_hash_lock, flags);
	}
	rcu_read_unlock();
}

void rswap_page_ext_copy(struct folio *newfolio, struct folio *folio)
{
	unsigned long i;
	unsigned long nr_pages = folio_nr_pages(folio);

	if (WARN_ON_ONCE(folio_nr_pages(newfolio) != nr_pages))
		return;

	for (i = 0; i < nr_pages; i++) {
		struct page_ext *old_ext = page_ext_get(folio_page(folio, i));
		struct page_ext *new_ext;
		struct rswap_page_ext *new_re;
		struct rswap_page_ext *old_re;
		unsigned long flags;

		if (!old_ext)
			continue;

		old_re = page_ext_data(old_ext, &rswap_page_ext_ops);
		if (!READ_ONCE(old_re->valid)) {
			page_ext_put(old_ext);
			continue;
		}

		new_ext = page_ext_get(folio_page(newfolio, i));
		if (!new_ext) {
			page_ext_put(old_ext);
			continue;
		}

		new_re = page_ext_data(new_ext, &rswap_page_ext_ops);
		spin_lock_irqsave(&rswap_hash_lock, flags);
		if (old_re->valid) {
			memcpy(new_re->hash, old_re->hash, SHA256_DIGEST_SIZE);
			WRITE_ONCE(new_re->valid, true);
		} else {
			WRITE_ONCE(new_re->valid, false);
		}
		spin_unlock_irqrestore(&rswap_hash_lock, flags);
		page_ext_put(old_ext);
		page_ext_put(new_ext);
	}
}

static struct rswap_hash *rswap_slot_lookup(struct swap_info_struct *si,
					    unsigned long offset)
{
	struct swap_cluster_info *ci;
	struct rswap_hash_table *table;

	if (offset >= si->max)
		return NULL;

	ci = __swap_offset_to_cluster(si, offset);
	/*
	 * Both pointers are published by rswap_slot_get() with
	 * cmpxchg_release(), so this side reads them with acquire: a reader that
	 * observes a slot must also observe the zeroed slot object and the table
	 * it lives in.
	 */
	table = smp_load_acquire(&ci->hash_table);
	if (!table)
		return NULL;

	/* Pair with the slot publication in rswap_slot_get(). */
	return smp_load_acquire(&table->hashes[offset % SWAPFILE_CLUSTER]);
}

/*
 * Return the slot of @offset, allocating the table and the slot on demand.
 * Allocation failure is not fatal: it only means that this page has no digest
 * slot yet, so @gfp has to fit the caller - the folio allocation path may
 * sleep (GFP_NOIO), the reclaim paths may not (GFP_NOWAIT).
 */
static struct rswap_hash *rswap_slot_get(struct swap_info_struct *si,
					 unsigned long offset, gfp_t gfp)
{
	struct swap_cluster_info *ci;
	struct rswap_hash_table *table, *new_table;
	struct rswap_hash *slot, *new_slot;
	unsigned int ci_off;

	if (offset >= si->max)
		return NULL;

	ci = __swap_offset_to_cluster(si, offset);
	ci_off = offset % SWAPFILE_CLUSTER;

	/* Same pairing as in rswap_slot_lookup(). */
	table = smp_load_acquire(&ci->hash_table);
	if (!table) {
		new_table = kzalloc_obj(*new_table, gfp);
		if (!new_table)
			return NULL;
		/*
		 * cmpxchg() is a relaxed read-modify-write: publishing with
		 * cmpxchg_release() is what orders the zeroed table before the
		 * pointer that makes it reachable, and what the acquire loads
		 * above pair with.
		 */
		table = cmpxchg_release(&ci->hash_table, NULL, new_table);
		if (table)
			kfree(new_table);
		else
			table = new_table;
	}

	/* Slots are published by cmpxchg_release() and read acquire here. */
	slot = smp_load_acquire(&table->hashes[ci_off]);
	if (slot)
		return slot;

	new_slot = kzalloc_obj(*new_slot, gfp);
	if (!new_slot)
		return NULL;

	slot = cmpxchg_release(&table->hashes[ci_off], NULL, new_slot);
	if (slot) {
		kfree(new_slot);
		return slot;
	}
	return new_slot;
}

/*
 * Store @hash in @slot and make it readable.
 *
 * The pointer published by rswap_slot_get() only makes the object reachable;
 * @valid is what publishes the digest bytes.  Clearing it first keeps a slot
 * that is reused for a new digest from exposing the bytes of the old one.
 */
static void rswap_hash_publish(struct rswap_hash *slot, const u8 *hash)
{
	smp_store_release(&slot->valid, 0);		/* old digest is gone */
	memcpy(slot->data, hash, RSWAP_HASH_LEN);
	smp_store_release(&slot->valid, 1);		/* digest is readable */
}

static int rswap_hash_store(struct swap_info_struct *si, swp_entry_t entry,
			    const u8 *hash)
{
	struct rswap_hash *slot;

	slot = rswap_slot_get(si, swp_offset(entry), GFP_NOWAIT);
	if (!slot)
		return -ENOMEM;

	rswap_hash_publish(slot, hash);
	return 0;
}

static bool rswap_hash_load(struct swap_info_struct *si, swp_entry_t entry,
			    u8 *hash)
{
	struct rswap_hash *slot = rswap_slot_lookup(si, swp_offset(entry));

	if (!slot)
		return false;

	/* Pair with rswap_hash_publish(): a reserved slot has no digest yet. */
	if (!smp_load_acquire(&slot->valid))
		return false;

	memcpy(hash, slot->data, RSWAP_HASH_LEN);
	return true;
}

/*
 * Resolve the digest user space supplied for @addr in @vma.
 *
 * The kernel never computes the digest itself.  User space attaches a
 * BPF_PROG_TYPE_SYSCALL program to the VMA and the kernel runs it with a
 * writable context: the program fills ctx->hash and returns non-zero.  That
 * program type may write to its context, which a raw tracepoint program
 * cannot.
 *
 * The anonymous caller runs under the page table lock, so the program must
 * not sleep and must not fault.
 *
 * The program is published into the VMA by rswap_attach_prog() and can be
 * replaced or detached at any time from a task that only holds the mmap lock in
 * write mode, which does not exclude the page table and rmap locks the callers
 * of this function hold.  The pointer is therefore loaded inside an RCU
 * read-side section, and that section is also what keeps the program alive:
 * bpf_prog_put() never frees a program synchronously, it defers the free through
 * a grace period (__bpf_prog_put_noref()), so a lookuper that fetched the
 * program before the detach still runs on live memory.
 */
static int rswap_hash_lookup(struct vm_area_struct *vma, unsigned long addr,
			     u8 *hash)
{
	struct rswap_hash_ctx ctx = { .vaddr = addr };
	struct bpf_prog *prog;
	int ret = -ENOENT;

	rcu_read_lock();
	prog = rcu_dereference(vma->rswap_prog);
	if (prog && bpf_prog_run(prog, &ctx)) {
		memcpy(hash, ctx.hash, RSWAP_HASH_LEN);
		ret = 0;
	}
	rcu_read_unlock();

	return ret;
}

/*
 * Reserve the slots of a folio that just entered the swap cache.  A reserved
 * slot is not valid: it reports "no digest" until rswap_attach_hash() or the
 * legacy page_ext fallback stores one.
 *
 * @gfp is the caller's context: folio_alloc_swap() runs while it may still
 * sleep and passes GFP_NOIO.  A failed reservation is not fatal - writeout
 * then takes its key from the page_ext fallback - but it does change where the
 * key comes from, so it is logged instead of passing silently.
 */
void rswap_prepare_hashes(struct folio *folio, gfp_t gfp)
{
	struct swap_info_struct *si;
	unsigned long i;

	if (!folio_test_swapcache(folio))
		return;

	si = __swap_entry_to_info(folio->swap);
	if (!(si->flags & SWP_RSWAP))
		return;

	for (i = 0; i < folio_nr_pages(folio); i++) {
		swp_entry_t entry = folio_swap_entry(folio, i);
		unsigned long offset = swp_offset(entry);

		if (rswap_slot_get(si, offset, gfp))
			continue;

		pr_warn_ratelimited("type %d offset %lu: no digest slot\n",
				    si->type, offset);
		return;
	}
}

/*
 * ---------- Per-VMA digest program ----------
 *
 * User space attaches a BPF program to a VMA; the kernel calls it to ask for
 * the digest of one base page.  The program stores the digest in the value of
 * an ARRAY map the kernel also holds, because the read-only raw tracepoint
 * context gives it nowhere else to write.
 */

void rswap_vma_dup(struct vm_area_struct *vma)
{
	/* Digests are a property of the mapping that attached them. */
	rcu_assign_pointer(vma->rswap_prog, NULL);
	vm_flags_clear(vma, VM_HASHED);
}

void rswap_vma_free(struct vm_area_struct *vma)
{
	struct bpf_prog *prog;

	prog = rcu_replace_pointer(vma->rswap_prog, NULL, true);
	if (prog)
		bpf_prog_put(prog);
}

/*
 * Attach @prog_fd to the VMA holding @vaddr.  A zero @prog_fd detaches.
 * Called from /sys/kernel/mm/xswap/rswap_attach.
 */
int rswap_attach_prog(unsigned long vaddr, int prog_fd)
{
	struct bpf_prog *prog = NULL, *old_prog;
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	int ret = 0;

	if (prog_fd) {
		prog = bpf_prog_get(prog_fd);
		if (IS_ERR(prog))
			return PTR_ERR(prog);
		/*
		 * The program writes the digest into its context, so the
		 * context it touches must fit the one we hand it.
		 */
		if (prog->type != BPF_PROG_TYPE_SYSCALL ||
		    prog->aux->max_ctx_offset > sizeof(struct rswap_hash_ctx)) {
			ret = -EINVAL;
			goto err;
		}
	}

	if (!mm) {
		ret = -ESRCH;
		goto err;
	}

	if (mmap_write_lock_killable(mm)) {
		ret = -EINTR;
		goto err;
	}
	vma = vma_lookup(mm, vaddr);
	if (!vma) {
		ret = -ENOENT;
		goto unlock;
	}

	old_prog = rcu_replace_pointer(vma->rswap_prog, prog, true);
	if (prog)
		vm_flags_set(vma, VM_HASHED);
	else
		vm_flags_clear(vma, VM_HASHED);

	mmap_write_unlock(mm);

	/*
	 * The replacement is published, so a lookup that runs now either sees
	 * @prog or the old one.  The old one is only dropped here, and its free is
	 * deferred by bpf_prog_put() through a grace period, so a lookup that
	 * already fetched it under rcu_read_lock() finishes on a live program.
	 */
	if (old_prog)
		bpf_prog_put(old_prog);
	return 0;

unlock:
	mmap_write_unlock(mm);
err:
	if (prog)
		bpf_prog_put(prog);
	return ret;
}

/* Free the digest slots of a cluster that is being released. */
void rswap_hash_table_free(struct swap_cluster_info *ci)
{
	struct rswap_hash_table *table = ci->hash_table;
	unsigned int i;

	if (!table)
		return;

	ci->hash_table = NULL;
	for (i = 0; i < SWAPFILE_CLUSTER; i++)
		kfree(table->hashes[i]);
	kfree(table);
}

/*
 * Anonymous folio: the swap entry exists and is about to replace the PTE, so
 * the digest goes straight into the slot that backs it.
 */
void rswap_attach_hash(swp_entry_t entry, unsigned long addr,
		       struct vm_area_struct *vma)
{
	struct swap_info_struct *si = __swap_entry_to_info(entry);
	struct rswap_hash *slot;
	u8 hash[RSWAP_HASH_LEN];

	if (!(si->flags & SWP_RSWAP))
		return;
	if (rswap_hash_lookup(vma, addr, hash))
		return;

	slot = rswap_slot_get(si, swp_offset(entry), GFP_NOWAIT);
	if (!slot)
		return;

	rswap_hash_publish(slot, hash);
}

/*
 * Shmem folio: shmem_writeout() allocates the swap entry only once the folio
 * is fully unmapped, so the digest is staged in the inode, keyed by page
 * index.  The index survives folio split and migration, which matters because
 * shmem_writeout() may split the folio before the entry exists.
 */
void rswap_attach_hash_shmem(struct folio *folio, unsigned long addr,
			     struct vm_area_struct *vma)
{
	struct address_space *mapping = folio_mapping(folio);
	struct shmem_inode_info *info;
	unsigned long i;

	if (!mapping || !shmem_mapping(mapping))
		return;
	/* Already in the swap cache: the digest belongs with its swap entry. */
	if (folio_test_swapcache(folio))
		return;

	info = SHMEM_I(mapping->host);

	for (i = 0; i < folio_nr_pages(folio); i++) {
		pgoff_t index = folio->index + i;
		struct rswap_hash *slot;
		void *old;
		u8 hash[RSWAP_HASH_LEN];

		if (rswap_hash_lookup(vma, addr + i * PAGE_SIZE, hash))
			continue;

		slot = kzalloc_obj(*slot, GFP_NOWAIT);
		if (!slot)
			continue;
		/* Digest first, so a reachable slot never has a stale one. */
		rswap_hash_publish(slot, hash);

		/*
		 * xa_store() takes ownership of @slot on success and returns
		 * the entry it replaced, which then belongs to this caller;
		 * @slot stays ours only if the store failed.  Freeing @slot on
		 * success would leave the xarray pointing at freed memory,
		 * which the later xa_erase() in rswap_shmem_move_hashes() and
		 * rswap_shmem_drop_hashes() reads or frees, and would leak the
		 * replaced slot.
		 */
		old = xa_store(&info->rswap_hashes, index, slot, GFP_NOWAIT);
		if (xa_is_err(old)) {
			kfree(slot);
			continue;
		}
		kfree(old);
	}
}

/*
 * Move the staged hashes of @folio into the slots of its new swap entries.
 *
 * The staged copy is dropped either way: the swap entry now owns the digest,
 * and a writeout that fails after this point has to be retried from a fresh
 * unmap, which resolves the digest again.
 */
void rswap_shmem_move_hashes(struct inode *inode, struct folio *folio)
{
	struct swap_info_struct *si;
	struct shmem_inode_info *info;
	unsigned long i;

	/*
	 * The caller has the shmem inode in hand: once the folio is in the swap
	 * cache, folio_mapping() reports the swap address space, not the inode
	 * that holds the staged digests.
	 */
	if (!folio_test_swapcache(folio))
		return;

	si = __swap_entry_to_info(folio->swap);
	if (!(si->flags & SWP_RSWAP))
		return;

	info = SHMEM_I(inode);

	for (i = 0; i < folio_nr_pages(folio); i++) {
		struct rswap_hash *staged, *slot;

		staged = xa_erase(&info->rswap_hashes, folio->index + i);
		if (!staged)
			continue;
		/* rswap_hash_publish() set this when the digest was staged. */
		if (!smp_load_acquire(&staged->valid)) {
			kfree(staged);
			continue;
		}

		slot = rswap_slot_get(si, swp_offset(folio_swap_entry(folio, i)),
				      GFP_NOWAIT);
		if (slot)
			rswap_hash_publish(slot, (const u8 *)staged->data);
		kfree(staged);
	}
}

void rswap_shmem_drop_hashes(struct inode *inode, pgoff_t start, pgoff_t end)
{
	struct shmem_inode_info *info = SHMEM_I(inode);
	pgoff_t index = start;

	while (index < end) {
		struct rswap_hash *slot;

		slot = xa_find(&info->rswap_hashes, &index, end - 1, XA_PRESENT);
		if (!slot)
			break;
		xa_erase(&info->rswap_hashes, index);
		kfree(slot);
		index++;
	}
}

void rswap_shmem_free_hashes(struct inode *inode)
{
	struct shmem_inode_info *info = SHMEM_I(inode);
	unsigned long index;
	void *slot;

	xa_for_each(&info->rswap_hashes, index, slot)
		kfree(slot);
	xa_destroy(&info->rswap_hashes);
}

/*
 * rswap_page_key - KV key for one base page, as a hex string.
 *
 * @page:  base page of the folio being written or read
 * @entry: swap entry that backs @page
 * @hex:   output buffer, at least RSWAP_HASH_HEXLEN + 1 bytes
 *
 * On write, use the digest that was resolved at unmap time; a page that
 * never got one falls back to the digest attached through
 * /proc/sys/vm/rswap/attach while that interface still exists.  On read, use
 * the stored digest so the key does not depend on the page still being in
 * swap cache.
 */
static int rswap_page_key(struct swap_info_struct *si, struct page *page,
			  swp_entry_t entry, int rw, char *hex)
{
	u8 hash[RSWAP_HASH_LEN];
	int ret;

	if (rw == WRITE) {
		if (!rswap_hash_load(si, entry, hash)) {
			/*
			 * Legacy fallback: a page_ext digest is a 32-byte
			 * SHA-256, zero extended to the slot width.
			 */
			memset(hash, 0, sizeof(hash));
			if (!rswap_page_get_hash(page, hash))
				return -ENODATA;
			ret = rswap_hash_store(si, entry, hash);
			if (ret)
				return ret;
		}
	} else if (!rswap_hash_load(si, entry, hash)) {
		return -ENOENT;
	}

	bin2hex(hex, hash, RSWAP_HASH_LEN);
	hex[RSWAP_HASH_HEXLEN] = '\0';
	return 0;
}

/* ---------- swap_ops implementations ---------- */

/*
 * rswap_submit_batch - Move one batch of base pages and copy reads back.
 *
 * @pages:	page images, already filled for a write
 * @targets:	folio pages the data belongs to
 * @nr:		number of pages in the batch
 * @rw:		WRITE or READ
 */
static int rswap_submit_batch(struct rswap_kv_page *pages, unsigned int nr,
			     int rw)
{
	int ret = 0;

	if (rw == WRITE)
		ret = rswap_kv_store(pages, nr, PAGE_SIZE);
	else
		ret = rswap_kv_load(pages, nr, PAGE_SIZE);

	return ret;
}

/*
 * Flush one batch: time it, move it, and account it per device and in total.
 * Pages of a failed batch count as failed, not as moved.
 */
static int rswap_flush_batch(struct rswap_kv_page *pages,
			     struct rswap_stats *stats, unsigned int nr, int rw)
{
	s64 started = ktime_get_ns();
	s64 elapsed;
	int ret;
	int i;

	ret = rswap_submit_batch(pages, nr, rw);
	elapsed = ktime_get_ns() - started;
	rswap_stats_io(rw == WRITE ? &rswap_write_io : &rswap_read_io, elapsed);

	if (!ret) {
		rswap_stats_pages(&rswap_total, rw, nr);
		for (i = 0; i < nr; i++)
			rswap_stats_pages(stats, rw, 1);
		return 0;
	}

	rswap_stats_errors(&rswap_total, rw, nr);
	for (i = 0; i < nr; i++)
		rswap_stats_errors(stats, rw, 1);
	return ret;
}

struct rswap_read_req;

/*
 * One batch of up to RSWAP_BATCH_MAX base page images: the keys they are
 * stored under, the folio pages they belong to and, for swapin, the work item
 * that moves them.  The page images never pass through the batch: a backend
 * moves them between the remote store and the folio pages @pages[].page names,
 * so a batch only carries bookkeeping.  Too big for the stack, so it is
 * allocated for the duration of the batch.
 *
 * A batch belongs to one asynchronous read request while it is queued or
 * running in a worker (@req is NULL on the synchronous write path).  It never
 * dereferences its swap device once it left the submitting task: the errors it
 * reports and the counters it updates come from @type and @stats, and @stats
 * holds a reference so the block outlives the device.  Keys and base page
 * addresses are resolved at submit time for the same reason.
 */
struct rswap_batch {
	struct rswap_stats	*stats;		/* referenced, may be NULL */
	unsigned int		type;		/* swap type, for diagnostics */
	unsigned int		nr;

	struct rswap_read_req	*req;		/* NULL on the synchronous path */
	struct work_struct	work;
	char			keys[RSWAP_BATCH_MAX][RSWAP_KV_KEY_LEN];
	struct rswap_kv_page	pages[RSWAP_BATCH_MAX];
};

static struct rswap_batch *rswap_batch_alloc(struct swap_info_struct *si)
{
	struct rswap_batch *batch;

	batch = kzalloc_obj(*batch, GFP_NOIO);
	if (unlikely(!batch))
		return NULL;

	/* Taken here, in the submitting task, while the device is pinned. */
	batch->stats = rswap_stats_get(si->rswap_stats);
	batch->type = si->type;

	return batch;
}

static void rswap_batch_free(struct rswap_batch *batch)
{
	if (!batch)
		return;
	rswap_stats_put(batch->stats);
	kfree(batch);
}

/*
 * Add the base page of @bv at @offset to @batch.
 *
 * The digest is looked up here, in the submitting task, so that a worker never
 * dereferences the swap device after the caller's context is gone.  Returns
 * -ENODATA on writeout resp. -ENOENT on swapin when the page has no digest.
 */
static int rswap_batch_add(struct rswap_batch *batch,
			   struct swap_info_struct *si, struct page *page,
			   int rw)
{
	struct folio *folio = page_folio(page);
	swp_entry_t entry = folio_page_swap_entry(folio, page);
	struct rswap_kv_page *kv_page = &batch->pages[batch->nr];
	char *key = batch->keys[batch->nr];
	int ret;

	ret = rswap_page_key(si, page, entry, rw, key);
	if (ret)
		return ret;

	kv_page->key = key;
	kv_page->page = page;
	batch->nr++;

	return 0;
}

/* Move a full or partial batch and empty it again. */
static int rswap_batch_flush(struct rswap_batch *batch, int rw)
{
	unsigned int nr = batch->nr;
	int ret;

	batch->nr = 0;
	ret = rswap_flush_batch(batch->pages, batch->stats, nr, rw);
	if (ret)
		pr_err_ratelimited("%s type %u failed: %d\n",
				   rw == WRITE ? "write" : "read",
				   batch->type, ret);
	return ret;
}

/*
 * Submit each base page synchronously and complete the whole swap request.
 *
 * Pages are collected into batches of up to RSWAP_BATCH_MAX so the backend
 * can move several pages per round trip; the batch is flushed whenever it is
 * full or the request runs out of pages.  Writeout always runs here; swapin
 * only gets here when no request bookkeeping memory was available.
 */
static void rswap_submit(struct swap_io_ctx *ctx, int rw)
{
	struct swap_iocb *sio = ctx->sio;
	struct iov_iter iter;
	struct rswap_batch *batch;
	struct folio *folio;
	struct page *page;
	unsigned int nr_moved = 0;
	unsigned int nr_left;
	int ret = 0;
	int i;
	unsigned int noio_flags;

	noio_flags = memalloc_noio_save();
	swap_fs_prepare_rw(ctx, rw, &iter);
	batch = rswap_batch_alloc(ctx->sis);
	if (!batch) {
		ret = -ENOMEM;
		goto out;
	}

	/*
	 * Swap-in can split or combine the folios used at swap-out. Store
	 * each base page under its own entry, independent of folio order.
	 */
	for (i = 0; i < sio->nr_bvecs; i++) {
		struct bio_vec *bv = &sio->bvecs[i];
		page = bv->bv_page;
		folio = page_folio(page);
		size_t offset;

		for (offset = 0; offset < bv->bv_len; offset += PAGE_SIZE, page++) {
			ret = rswap_batch_add(batch, ctx->sis, page, rw);
			if (ret)
				goto key_error;
			if (batch->nr < RSWAP_BATCH_MAX)
				continue;
			nr_moved += batch->nr;
			ret = rswap_batch_flush(batch, rw);
			if (ret)
				goto out;
		}
	}
	if (batch->nr) {
		nr_moved += batch->nr;
		ret = rswap_batch_flush(batch, rw);
	}
	goto out;

key_error:
	/*
	 * A key error fails the whole request, so every page that did not move
	 * is a failed page, exactly as in the batch-failure path: the pages of
	 * the batch that was not flushed, the failing page and the pages the
	 * loop had not reached yet.
	 */
	nr_left = (sio->len >> PAGE_SHIFT) - nr_moved - batch->nr;
	rswap_stats_key_failure(&rswap_total, rw, ret, nr_left);
	rswap_stats_key_failure(batch->stats, rw, ret, nr_left);
	pr_err_ratelimited("%s type %u offset %lu failed: %d\n",
			   rw == WRITE ? "write" : "read",
			   ctx->sis->type,
			   swp_offset(folio_page_swap_entry(folio, page)),
			   ret);
out:
	rswap_batch_free(batch);
	memalloc_noio_restore(noio_flags);
	sio->iocb.ki_complete(&sio->iocb, ret < 0 ? ret : sio->len);
}

/* ---------- asynchronous swapin ---------- */

/*
 * How many read batches may be outstanding at once.  A batch is bookkeeping
 * only - RSWAP_BATCH_MAX keys and one struct rswap_kv_page per page, a few
 * KiB - so what this bound really limits is the folios a queued batch pins
 * until its remote reads finished.  Eight matches
 * RSWAP_REDIS_POOL_MAX: a ninth concurrent batch would only wait for a pooled
 * connection, and the measured WILLNEED throughput of the remote Redis test
 * server stopped improving beyond eight concurrent batches (22.5 MiB/s with
 * eight callers against 9.7 MiB/s with one).
 */
#define RSWAP_READ_MAX_INFLIGHT	8

/*
 * Batches holding one of the RSWAP_READ_MAX_INFLIGHT slots: queued or running
 * in a worker, or moved in the submitting task while a slot was free.
 */
static atomic_t rswap_read_inflight;
/* Largest value the above reached; reset when a device is created. */
static atomic_t rswap_read_peak_inflight;
/* Batches moved in the submitting task instead (queue full or absent). */
static atomic64_t rswap_read_fallbacks;
/* Submissions and the time they spent before returning to the caller. */
static atomic64_t rswap_read_submits;
static atomic64_t rswap_read_submit_ns;

/*
 * Reads run on their own workqueue.  More than one worker is the point:
 * MADV_WILLNEED submits from a single task, and overlapping the remote round
 * trips is what turns one caller into the throughput of several.  The
 * workqueue lives for the whole boot; the backend can never change, so there
 * is nothing to tear it down for.
 */
static struct workqueue_struct *rswap_read_wq;

static void rswap_read_peak_update(int value)
{
	int old = atomic_read(&rswap_read_peak_inflight);

	while (old < value &&
	       !atomic_try_cmpxchg(&rswap_read_peak_inflight, &old, value))
		;
}

/* Take one of the RSWAP_READ_MAX_INFLIGHT slots; false when saturated. */
static bool rswap_read_enter(void)
{
	int value = atomic_read(&rswap_read_inflight);

	do {
		if (value >= RSWAP_READ_MAX_INFLIGHT)
			return false;
	} while (!atomic_try_cmpxchg(&rswap_read_inflight, &value, value + 1));

	rswap_read_peak_update(value + 1);
	return true;
}

/*
 * Release @nr read slots.  A batch releases its slot only after it dropped its
 * request reference, i.e. after the completion it may have triggered ran: a
 * worker in rswap_read_batch_work(), a batch moved in the submitting task in
 * rswap_read_async() after its final drop.
 */
static void rswap_read_leave(unsigned int nr)
{
	atomic_sub(nr, &rswap_read_inflight);
}

/*
 * One asynchronous read request.  The submitting task holds one reference and
 * every batch handed to the workqueue holds one more, so the last batch to
 * finish reports the request result - after all batches finished, and exactly
 * once.
 */
struct rswap_read_req {
	struct swap_iocb	*sio;
	refcount_t		refs;
	atomic_t		error;		/* first negative errno, 0 if none */
};

/* Keep the first failure; a request either fully succeeds or fully fails. */
static void rswap_read_req_error(struct rswap_read_req *req, int ret)
{
	int error = 0;

	if (ret < 0)
		atomic_try_cmpxchg(&req->error, &error, ret);
}

/*
 * Report the request result.  swap_read_end() releases the swap_iocb, so
 * nothing may touch @req or its sio after this returns.
 */
static void rswap_read_request_end(struct rswap_read_req *req)
{
	struct swap_iocb *sio = req->sio;
	int ret = atomic_read(&req->error);

	kfree(req);
	sio->iocb.ki_complete(&sio->iocb, ret ? ret : sio->len);
}

static void rswap_read_req_put(struct rswap_read_req *req)
{
	if (refcount_dec_and_test(&req->refs))
		rswap_read_request_end(req);
}

/* One worker batch: move it, account it, drop one request reference. */
static void rswap_read_batch_work(struct work_struct *work)
{
	struct rswap_batch *batch = container_of(work, struct rswap_batch, work);
	struct rswap_read_req *req = batch->req;
	unsigned int noio_flags;
	int ret;

	noio_flags = memalloc_noio_save();
	ret = rswap_batch_flush(batch, READ);
	memalloc_noio_restore(noio_flags);

	rswap_read_req_error(req, ret);
	rswap_batch_free(batch);
	rswap_read_req_put(req);
	rswap_read_leave(1);
}

/*
 * Hand one batch to a worker, or move it in the submitting task when the
 * queue is saturated, the workqueue is unavailable or it refuses the item.
 * The inline path is exactly the previous synchronous behaviour, so swapin
 * always makes forward progress under memory pressure.
 *
 * Returns true when the batch was moved here and holds a read slot, which the
 * submitting task releases after its final reference drop.
 */
static bool rswap_read_dispatch(struct rswap_batch *batch)
{
	struct rswap_read_req *req = batch->req;
	bool held;
	int ret;

	held = rswap_read_enter();
	if (held && rswap_read_wq) {
		refcount_inc(&req->refs);
		INIT_WORK(&batch->work, rswap_read_batch_work);
		if (queue_work(rswap_read_wq, &batch->work))
			return false;
		refcount_dec(&req->refs);
		rswap_read_leave(1);
		held = false;
	}

	/*
	 * Move the batch here instead.  Either the queue was saturated, so no
	 * slot was taken and read_inflight cannot exceed the bound, or there is
	 * no workqueue and the slot taken above stays held until the submitter
	 * dropped its final reference.
	 */
	atomic64_inc(&rswap_read_fallbacks);
	ret = rswap_batch_flush(batch, READ);
	rswap_read_req_error(req, ret);
	rswap_batch_free(batch);

	return held;
}

static int rswap_read_wq_init(void)
{
	struct workqueue_struct *wq;

	if (rswap_read_wq)
		return 0;
	/* WQ_MEM_RECLAIM: the workers must run while reclaim waits for them. */
	wq = alloc_workqueue("rswap_read", WQ_MEM_RECLAIM,
			     RSWAP_READ_MAX_INFLIGHT);
	if (!wq) {
		pr_warn("no read workqueue, swapin stays synchronous\n");
		return -ENOMEM;
	}
	if (cmpxchg(&rswap_read_wq, NULL, wq))
		destroy_workqueue(wq);
	return 0;
}

/*
 * rswap_read_async - Queue the reads of one swap request and return.
 *
 * Everything that needs the swap device - the per-entry digest lookup, the
 * base page addressing - happens here, in the submitting task, as does the
 * preparation of the completion callback.  The batches themselves are moved
 * by the read workqueue, which calls sio->iocb.ki_complete() once every batch
 * of the request finished, i.e. through the normal asynchronous swapin
 * lifecycle.
 *
 * Batch bookkeeping is kzalloc'ed under GFP_NOIO one batch at a time, so the
 * submitter never needs memory for the whole request.  When even that fails,
 * or no batch slot is free, the batch is moved right here.
 */
static void rswap_read_async(struct swap_io_ctx *ctx)
{
	struct swap_iocb *sio = ctx->sio;
	struct iov_iter iter;
	struct rswap_read_req *req;
	struct rswap_batch *batch;
	struct folio *folio;
	struct page *page;
	unsigned int nr_queued = 0;
	unsigned int nr_inline = 0;
	unsigned int nr_left;
	s64 started = ktime_get_ns();
	unsigned int noio_flags;
	int ret = 0;
	int i;

	noio_flags = memalloc_noio_save();
	req = kzalloc_obj(*req, GFP_NOIO);
	if (!req) {
		/* No bookkeeping memory: do what rswap always did. */
		memalloc_noio_restore(noio_flags);
		rswap_submit(ctx, READ);
		return;
	}
	req->sio = sio;
	refcount_set(&req->refs, 1);
	/* Set sio->iocb.ki_complete before any batch can be published. */
	swap_fs_prepare_rw(ctx, READ, &iter);

	batch = rswap_batch_alloc(ctx->sis);
	if (!batch) {
		ret = -ENOMEM;
		goto out_error;
	}

	/*
	 * Swap-in can split or combine the folios used at swap-out. Store
	 * each base page under its own entry, independent of folio order.
	 */
	for (i = 0; i < sio->nr_bvecs; i++) {
		struct bio_vec *bv = &sio->bvecs[i];
		page = bv->bv_page;
		folio = page_folio(page);
		size_t offset;

		for (offset = 0; offset < bv->bv_len; offset += PAGE_SIZE, page++) {
			ret = rswap_batch_add(batch, ctx->sis, page, READ);
			if (ret)
				goto key_error;
			if (batch->nr < RSWAP_BATCH_MAX)
				continue;

			batch->req = req;
			nr_queued += batch->nr;
			if (rswap_read_dispatch(batch))
				nr_inline++;
			batch = rswap_batch_alloc(ctx->sis);
			if (!batch) {
				ret = -ENOMEM;
				goto out_error;
			}
		}
	}
	if (batch->nr) {
		batch->req = req;
		nr_queued += batch->nr;
		if (rswap_read_dispatch(batch))
			nr_inline++;
		batch = NULL;
	}
	goto out;

key_error:
	/*
	 * A key error fails the whole request.  The batches already handed to
	 * the workers account their own pages when they complete, so fail
	 * everything else: the pages of the batch that was not dispatched, the
	 * failing page and the pages the loop had not reached yet.
	 */
	nr_left = (sio->len >> PAGE_SHIFT) - nr_queued - batch->nr;
	rswap_stats_key_failure(&rswap_total, READ, ret, nr_left);
	rswap_stats_key_failure(batch->stats, READ, ret, nr_left);
	pr_err_ratelimited("read type %u offset %lu failed: %d\n",
			   ctx->sis->type,
			   swp_offset(folio_page_swap_entry(folio, page)),
			   ret);
out_error:
	rswap_read_req_error(req, ret);
out:
	rswap_batch_free(batch);
	memalloc_noio_restore(noio_flags);
	atomic64_inc(&rswap_read_submits);
	atomic64_add(ktime_get_ns() - started, &rswap_read_submit_ns);
	/* Drop the submitting task's reference; the last batch completes. */
	rswap_read_req_put(req);
	/* The request ran; release the slots of the batches moved here. */
	rswap_read_leave(nr_inline);
}

static void rswap_submit_write(struct swap_io_ctx *ctx)
{
	rswap_submit(ctx, WRITE);
}

/*
 * rswap_submit_read - Queue folio reads from the selected KV backend.
 *
 * Called from swap_read_submit().  Returns once every batch is dispatched;
 * the folios are unlocked by the normal completion callback when the remote
 * reads finished.
 */
static void rswap_submit_read(struct swap_io_ctx *ctx)
{
	rswap_read_async(ctx);
}

/* Can every base page of @folio be moved right now? */
static bool rswap_folio_ready(struct folio *folio, int rw)
{
	unsigned long i;

	for (i = 0; i < folio_nr_pages(folio); i++) {
		swp_entry_t entry = folio_swap_entry(folio, i);
		struct swap_info_struct *si = __swap_entry_to_info(entry);
		u8 hash[RSWAP_HASH_LEN];

		if (rw == WRITE) {
			if (rswap_hash_load(si, entry, hash))
				continue;
			memset(hash, 0, sizeof(hash));
			if (!rswap_page_get_hash(folio_page(folio, i), hash))
				return false;
		} else if (!rswap_hash_load(si, entry, hash)) {
			return false;
		}
	}
	return true;
}

/*
 * rswap_can_merge - Can @folio share a request with @prev_folio?
 *
 * Merging is what lets one KV round trip carry several pages; without it every
 * folio is its own request and the round trip cost is paid per page.
 *
 * A page that cannot be moved must not drag its neighbours down with it: the
 * swap core fails a whole request at once, so a folio whose pages have no
 * attached digest (writeout) resp. no stored digest (swapin) is submitted on
 * its own and only it fails and stays resident.  That is why @prev_folio is
 * re-checked as well: it may have started the request without being asked.
 */
static bool rswap_can_merge(struct folio *folio, struct folio *prev_folio,
			    size_t prev_folio_size, int rw)
{
	return rswap_folio_ready(prev_folio, rw) &&
	       rswap_folio_ready(folio, rw);
}

/* The rswap operations vector. */
static const struct swap_ops kv_swap_ops = {
	.flags		= SWAP_OPS_F_REQUIRE_NOFS,
	.submit_write	= rswap_submit_write,
	.submit_read	= rswap_submit_read,
	.can_merge	= rswap_can_merge,
};

/* ---------- sysctl: attach digests to pages ---------- */

static int rswap_attach_page(unsigned long vaddr, const u8 *hash)
{
	struct page *pinned_page;
	struct folio *folio;
	struct page *page;
	int got;
	int ret;

	vaddr = untagged_addr(vaddr) & PAGE_MASK;
	got = pin_user_pages_fast(vaddr, 1, 0, &pinned_page);
	if (got != 1)
		return got < 0 ? got : -EFAULT;

	folio = page_folio(pinned_page);
	if (is_zero_page(pinned_page) || !folio_test_anon(folio)) {
		ret = -EINVAL;
		goto unpin;
	}

	page = folio_page(folio, folio_page_idx(folio, pinned_page));
	ret = rswap_page_set_hash(page, hash);
unpin:
	unpin_user_page(pinned_page);
	return ret;
}

/*
 * echo "<vaddr> <sha256>" > /proc/sys/vm/rswap/attach
 */
static int rswap_attach_sysctl(const struct ctl_table *table, int write,
			       void *buffer, size_t *lenp, loff_t *ppos)
{
	char *str;
	char *line;
	char *hash_str;
	unsigned long vaddr;
	u8 hash[SHA256_DIGEST_SIZE];
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!write)
		return -EINVAL;
	if (*lenp >= PAGE_SIZE)
		return -EINVAL;

	str = kstrndup(buffer, *lenp, GFP_KERNEL);
	if (!str)
		return -ENOMEM;

	line = strim(str);
	hash_str = strpbrk(line, " \t");
	if (!hash_str) {
		ret = -EINVAL;
		goto out;
	}
	*hash_str++ = '\0';
	hash_str = strim(hash_str);

	if (kstrtoul(line, 16, &vaddr) ||
	    strlen(hash_str) != RSWAP_SHA256_HEXLEN ||
	    hex2bin(hash, hash_str, SHA256_DIGEST_SIZE)) {
		ret = -EINVAL;
		goto out;
	}

	ret = rswap_attach_page(vaddr, hash);
	if (ret)
		goto out;

	*ppos += *lenp;
out:
	kfree(str);
	return ret;
}

static const struct ctl_table rswap_sysctls[] = {
	{
		.procname	= "attach",
		.mode		= 0200,
		.proc_handler	= rswap_attach_sysctl,
	},
};

static int __init rswap_sysctl_init(void)
{
	register_sysctl_init("vm/rswap", rswap_sysctls);
	return 0;
}
late_initcall(rswap_sysctl_init);

/* ---------- Device setup / teardown ---------- */

static int rswap_stats_alloc(struct swap_info_struct *si)
{
	si->rswap_stats = kzalloc_obj(*si->rswap_stats, GFP_KERNEL);
	if (!si->rswap_stats)
		return -ENOMEM;
	/* The device holds the first reference; batches take their own. */
	refcount_set(&si->rswap_stats->refs, 1);
	return 0;
}

static void rswap_stats_free(struct swap_info_struct *si)
{
	rswap_stats_put(si->rswap_stats);
	si->rswap_stats = NULL;
}

/*
 * Called when a swap entry is released, before the slot can be reused.  The
 * digest must not survive into the next user of the slot: it is the only
 * thing that keeps a key from being reused for different page contents.
 */
void rswap_hash_invalidate(struct swap_info_struct *si, unsigned long offset,
			   unsigned int nr_entries)
{
	unsigned long end;

	if (offset >= si->max)
		return;

	end = offset + min_t(unsigned long, nr_entries, si->max - offset);
	for (; offset < end; offset++) {
		struct rswap_hash *slot;

		slot = rswap_slot_lookup(si, offset);
		if (!slot)
			continue;

		/*
		 * The swap slot is about to be reused; a published digest must not
		 * outlive it, or the next page in the slot would be stored under the
		 * key of the previous one.  Only @valid is cleared: the object stays
		 * owned by the cluster and is freed by rswap_hash_table_free().
		 * Lookups are lock-free, so a kfree() here would be a use after
		 * free, and one slot per swap offset is the bound on this memory.
		 * Pair with rswap_hash_load().
		 */
		smp_store_release(&slot->valid, 0);
	}
}

int rswap_enable(struct swap_info_struct *si)
{
	int ret;

	if (!(si->flags & SWP_XSWAP))
		return -EINVAL;

	/* Never hand I/O to a device whose store was never set up. */
	if (!rswap_backend)
		return -ENODEV;

	/* Best effort: without it swapin simply stays synchronous. */
	rswap_read_wq_init();
	atomic_set(&rswap_read_peak_inflight, 0);

	ret = rswap_stats_alloc(si);
	if (ret)
		return ret;

	/*
	 * Register our swap_ops.  From this point on, the swap core calls
	 * rswap_submit_write / rswap_submit_read for I/O on this device.
	 *
	 * swap_fs_activate() returns the result of add_swap_extent(), which
	 * returns 0 (merge) or 1 (new extent) on success.  Map both to 0 so
	 * the caller can use the conventional if (ret < 0) error check.
	 */
	ret = swap_fs_activate(si, &kv_swap_ops);
	if (ret < 0) {
		rswap_stats_free(si);
		return ret;
	}
	return 0;
}

void rswap_disable(struct swap_info_struct *si)
{
	/*
	 * Reclaim waits for the writeback flag that writeout clears, but a read
	 * batch still completes its request from the worker and unlocks the folios
	 * it holds, so drain the read workqueue here.
	 *
	 * The counter block is not freed here and si->rswap_stats is left as it is:
	 * a batch does not reach back into the device, it carries its own reference
	 * to the counters (struct rswap_batch), and the block is freed by whichever
	 * rswap_stats_put() releases the last reference - i.e. only once neither a
	 * worker nor a queued batch can observe it any more.  The debugfs file that
	 * reads the block is removed by the swap core as part of the teardown.
	 *
	 * The digest slots themselves belong to the swap clusters, which are
	 * released by the swap core, so nothing else is ours to free here.
	 */
	if (rswap_read_wq)
		flush_workqueue(rswap_read_wq);
	rswap_stats_put(si->rswap_stats);
}

void rswap_swapoff(struct swap_info_struct *si)
{
	rswap_disable(si);
}

/* ---------- debugfs interface ---------- */

static struct dentry *rswap_debugfs_root;
/*
 * debugfs_create_str() wants a stable char **, so point it at the resolved
 * backend name and endpoint, both of which live for the whole boot.
 */
static char *rswap_debugfs_backend = (char *)"none";
static char *rswap_debugfs_endpoint = rswap_backend_endpoint;

#ifdef CONFIG_DEBUG_FS
static u64 rswap_stats_avg(atomic64_t *total, atomic64_t *batches)
{
	u64 count = atomic64_read(batches);

	return count ? div_u64(atomic64_read(total), count) : 0;
}

/* Backend-wide counters: /sys/kernel/debug/rswap/stats */
static int rswap_stats_show(struct seq_file *m, void *unused)
{
	u64 written = atomic64_read(&rswap_total.pages_written);
	u64 read = atomic64_read(&rswap_total.pages_read);

	seq_printf(m, "backend\t\t%s\n", rswap_backend ? rswap_backend->name :
		   "none");
	seq_printf(m, "endpoint\t%s\n", rswap_backend_endpoint);
	seq_printf(m, "batch_max\t%u\n", RSWAP_BATCH_MAX);
	seq_printf(m, "written_pages\t%llu\n", written);
	seq_printf(m, "written_bytes\t%llu\n", written << PAGE_SHIFT);
	seq_printf(m, "written_batches\t%llu\n",
		   atomic64_read(&rswap_write_io.batches));
	seq_printf(m, "written_errors\t%llu\n",
		   atomic64_read(&rswap_total.errors_written));
	seq_printf(m, "written_no_digest\t%llu\n",
		   atomic64_read(&rswap_total.no_digest));
	seq_printf(m, "written_avg_ns\t%llu\n",
		   rswap_stats_avg(&rswap_write_io.ns, &rswap_write_io.batches));
	seq_printf(m, "written_max_ns\t%llu\n",
		   atomic64_read(&rswap_write_io.max_ns));
	seq_printf(m, "read_pages\t%llu\n", read);
	seq_printf(m, "read_bytes\t%llu\n", read << PAGE_SHIFT);
	seq_printf(m, "read_batches\t%llu\n",
		   atomic64_read(&rswap_read_io.batches));
	seq_printf(m, "read_errors\t%llu\n",
		   atomic64_read(&rswap_total.errors_read));
	seq_printf(m, "read_no_entry\t%llu\n",
		   atomic64_read(&rswap_total.no_entry));
	seq_printf(m, "read_avg_ns\t%llu\n",
		   rswap_stats_avg(&rswap_read_io.ns, &rswap_read_io.batches));
	seq_printf(m, "read_max_ns\t%llu\n",
		   atomic64_read(&rswap_read_io.max_ns));
	seq_printf(m, "read_inflight\t%u\n",
		   atomic_read(&rswap_read_inflight));
	seq_printf(m, "read_peak_inflight\t%u\n",
		   atomic_read(&rswap_read_peak_inflight));
	seq_printf(m, "read_fallbacks\t%llu\n",
		   atomic64_read(&rswap_read_fallbacks));
	seq_printf(m, "read_submits\t%llu\n",
		   atomic64_read(&rswap_read_submits));
	seq_printf(m, "read_submit_avg_ns\t%llu\n",
		   rswap_stats_avg(&rswap_read_submit_ns, &rswap_read_submits));
	if (rswap_backend && rswap_backend->show_stats)
		rswap_backend->show_stats(m);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(rswap_stats);

/* Per-device counters: /sys/kernel/debug/rswap/type<N>/stats */
static int rswap_dev_stats_show(struct seq_file *m, void *unused)
{
	struct swap_info_struct *si = m->private;
	struct rswap_stats *stats = si->rswap_stats;

	if (!stats)
		return 0;
	seq_printf(m, "pages_written\t%llu\n",
		   atomic64_read(&stats->pages_written));
	seq_printf(m, "errors_written\t%llu\n",
		   atomic64_read(&stats->errors_written));
	seq_printf(m, "no_digest\t%llu\n", atomic64_read(&stats->no_digest));
	seq_printf(m, "pages_read\t%llu\n",
		   atomic64_read(&stats->pages_read));
	seq_printf(m, "errors_read\t%llu\n",
		   atomic64_read(&stats->errors_read));
	seq_printf(m, "no_entry\t%llu\n", atomic64_read(&stats->no_entry));
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(rswap_dev_stats);
#endif /* CONFIG_DEBUG_FS */

/*
 * Create the rswap debugfs tree once, before any device can exist, so the
 * backend counters are readable even when no rswap device is active.
 */
static void __init rswap_debugfs_init(void)
{
	rswap_debugfs_root = debugfs_create_dir("rswap", NULL);
	if (IS_ERR_OR_NULL(rswap_debugfs_root))
		return;

	if (rswap_backend)
		rswap_debugfs_backend = (char *)rswap_backend->name;
	debugfs_create_str("backend", 0444, rswap_debugfs_root,
			   &rswap_debugfs_backend);
	debugfs_create_str("endpoint", 0444, rswap_debugfs_root,
			   &rswap_debugfs_endpoint);
#ifdef CONFIG_DEBUG_FS
	debugfs_create_file("stats", 0444, rswap_debugfs_root, NULL,
			    &rswap_stats_fops);
#endif
}

void rswap_debugfs_add(struct swap_info_struct *si)
{
	struct dentry *dentry;
	char name[32];

	if (IS_ERR_OR_NULL(rswap_debugfs_root))
		return;

	snprintf(name, sizeof(name), "type%d", si->type);
	dentry = debugfs_create_dir(name, rswap_debugfs_root);
	if (IS_ERR_OR_NULL(dentry))
		return;

	/*
	 * Store the port in a heap-allocated variable so debugfs can
	 * safely reference it.  Freed when the dentry is removed.
	 */
	si->rswap_kv_port = kmalloc_obj(*si->rswap_kv_port, GFP_KERNEL);
	if (si->rswap_kv_port) {
		*si->rswap_kv_port = rswap_backend_cfg.port;
		debugfs_create_u32("kv_port", 0444, dentry, si->rswap_kv_port);
	}
#ifdef CONFIG_DEBUG_FS
	if (si->rswap_stats)
		debugfs_create_file("stats", 0444, dentry, si,
				    &rswap_dev_stats_fops);
#endif
}

void rswap_debugfs_del(struct swap_info_struct *si)
{
	char name[32];

	if (!rswap_debugfs_root)
		goto free_port;

	snprintf(name, sizeof(name), "type%d", si->type);
	debugfs_lookup_and_remove(name, rswap_debugfs_root);

free_port:
	kfree(si->rswap_kv_port);
	si->rswap_kv_port = NULL;
}
