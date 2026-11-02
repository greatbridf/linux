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
 * The digest is supplied by user space, which knows what a page holds and
 * attaches the digest to it through /proc/sys/vm/rswap/attach.  The digest
 * is kept in page_ext until writeout, then copied into a per-device table
 * indexed by swap offset.  Swapin uses that table entry as the KV key, so
 * the key does not depend on the page remaining in the swap cache.  Pages
 * without an attached digest cannot be written to rswap.
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
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/page_ext.h>
#include <linux/sysctl.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/uio.h>

#include "swap.h"
#include "rswap.h"
#include "rswap_backend.h"

/* ---------- Configuration ---------- */

#define RSWAP_SHA256_HEXLEN	64	/* SHA-256 -> 64 hex chars */

static_assert(RSWAP_SHA256_HEXLEN + 1 == RSWAP_KV_KEY_LEN);

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
MODULE_PARM_DESC(host, "KV endpoint address; empty selects the backend default");

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

static const __initconst struct rswap_backend *rswap_backends[] = {
#ifdef CONFIG_RSWAP_KV_HTTP
	&rswap_http_backend,
#endif
#ifdef CONFIG_RSWAP_KV_REDIS
	&rswap_redis_backend,
#endif
};

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

struct rswap_hash_entry {
	u8	hash[SHA256_DIGEST_SIZE];
	u8	valid;
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

static struct rswap_hash_entry *rswap_hash_slot(struct swap_info_struct *si,
						swp_entry_t entry)
{
	unsigned long offset = swp_offset(entry);

	if (!si->rswap_hashes || offset >= si->max)
		return NULL;
	return &si->rswap_hashes[offset];
}

static int rswap_hash_store(struct swap_info_struct *si, swp_entry_t entry,
			    const u8 *hash)
{
	struct rswap_hash_entry *slot = rswap_hash_slot(si, entry);

	if (!slot)
		return -ENOENT;

	memcpy(slot->hash, hash, SHA256_DIGEST_SIZE);
	/* Publish the digest before marking the slot valid. */
	smp_store_release(&slot->valid, 1);
	return 0;
}

static bool rswap_hash_load(struct swap_info_struct *si, swp_entry_t entry,
			    u8 *hash)
{
	struct rswap_hash_entry *slot = rswap_hash_slot(si, entry);

	/* Pair with rswap_hash_store() before reading the digest. */
	if (!slot || !smp_load_acquire(&slot->valid))
		return false;

	memcpy(hash, slot->hash, SHA256_DIGEST_SIZE);
	return true;
}

/*
 * rswap_page_key - KV key for one base page, as a hex string.
 *
 * @page:  base page of the folio being written or read
 * @entry: swap entry that backs @page
 * @hex:   output buffer, at least RSWAP_SHA256_HEXLEN + 1 bytes
 *
 * On write, persist the digest attached to @page in the device table.  On
 * read, use the persisted digest so the key does not depend on the page
 * still being in swap cache.
 */
static int rswap_page_key(struct swap_info_struct *si, struct page *page,
			  swp_entry_t entry, int rw, char *hex)
{
	u8 hash[SHA256_DIGEST_SIZE];
	int ret;

	if (rw == WRITE) {
		if (!rswap_page_get_hash(page, hash))
			return -ENODATA;
		ret = rswap_hash_store(si, entry, hash);
		if (ret)
			return ret;
	} else if (!rswap_hash_load(si, entry, hash)) {
		return -ENOENT;
	}

	bin2hex(hex, hash, SHA256_DIGEST_SIZE);
	hex[RSWAP_SHA256_HEXLEN] = '\0';
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
static int rswap_submit_batch(struct rswap_kv_page *pages,
			      struct page *const *targets, unsigned int nr,
			      int rw)
{
	void *mapped;
	int ret;
	int i;

	if (rw == WRITE)
		ret = rswap_kv_store(pages, nr, PAGE_SIZE);
	else
		ret = rswap_kv_load(pages, nr, PAGE_SIZE);
	if (ret)
		return ret;

	if (rw == READ) {
		for (i = 0; i < nr; i++) {
			mapped = kmap_local_page(targets[i]);
			memcpy(mapped, pages[i].data, PAGE_SIZE);
			kunmap_local(mapped);
		}
	}
	return 0;
}

/*
 * Submit each base page synchronously and complete the whole swap request.
 *
 * Pages are collected into batches of up to RSWAP_BATCH_MAX so the backend
 * can move several pages per round trip; the batch is flushed whenever it is
 * full or the request runs out of pages.
 */
static void rswap_submit(struct swap_io_ctx *ctx, int rw)
{
	struct swap_iocb *sio = ctx->sio;
	struct iov_iter iter;
	char keys[RSWAP_BATCH_MAX][RSWAP_SHA256_HEXLEN + 1];
	struct rswap_kv_page pages[RSWAP_BATCH_MAX];
	struct page *targets[RSWAP_BATCH_MAX];
	unsigned int nr = 0;
	swp_entry_t batch_entry = { };
	swp_entry_t cur_entry = { };
	char *data = NULL;
	int ret = 0;
	int i;
	unsigned int noio_flags;

	noio_flags = memalloc_noio_save();
	swap_fs_prepare_rw(ctx, rw, &iter);
	data = kvmalloc_array(RSWAP_BATCH_MAX, PAGE_SIZE, GFP_NOIO);
	if (!data) {
		ret = -ENOMEM;
		goto out;
	}

	/*
	 * Swap-in can split or combine the folios used at swap-out. Store
	 * each base page under its own entry, independent of folio order.
	 */
	for (i = 0; i < sio->nr_bvecs; i++) {
		struct bio_vec *bv = &sio->bvecs[i];
		struct folio *folio = bvec_folio(bv);
		size_t offset;

		for (offset = 0; offset < bv->bv_len; offset += PAGE_SIZE) {
			size_t folio_offset =
				folio_page_idx(folio, bv->bv_page) * PAGE_SIZE +
				bv->bv_offset + offset;
			unsigned int idx = folio_offset / PAGE_SIZE;
			struct page *page = folio_page(folio, idx);
			swp_entry_t entry = folio_swap_entry(folio, idx);
			struct swap_info_struct *si =
				__swap_entry_to_info(entry);
			void *mapped;

			cur_entry = entry;
			ret = rswap_page_key(si, page, entry, rw, keys[nr]);
			if (ret)
				goto io_error;

			if (!nr)
				batch_entry = entry;
			pages[nr].key = keys[nr];
			pages[nr].data = data + nr * PAGE_SIZE;
			targets[nr] = page;
			if (rw == WRITE) {
				mapped = kmap_local_page(page);
				memcpy(pages[nr].data, mapped, PAGE_SIZE);
				kunmap_local(mapped);
			}
			nr++;

			if (nr < RSWAP_BATCH_MAX)
				continue;
			ret = rswap_submit_batch(pages, targets, nr, rw);
			if (ret)
				goto batch_error;
			nr = 0;
		}
	}
	if (nr) {
		ret = rswap_submit_batch(pages, targets, nr, rw);
		if (ret)
			goto batch_error;
	}
	goto out;

batch_error:
	pr_err_ratelimited("%s type %u offset %lu..%lu failed: %d\n",
			   rw == WRITE ? "write" : "read",
			   swp_type(batch_entry), swp_offset(batch_entry),
			   swp_offset(batch_entry) + nr - 1, ret);
	goto out;
io_error:
	pr_err_ratelimited("%s type %u offset %lu failed: %d\n",
			   rw == WRITE ? "write" : "read",
			   swp_type(cur_entry), swp_offset(cur_entry), ret);
out:
	kvfree(data);
	memalloc_noio_restore(noio_flags);
	sio->iocb.ki_complete(&sio->iocb, ret < 0 ? ret : sio->len);
}

static void rswap_submit_write(struct swap_io_ctx *ctx)
{
	rswap_submit(ctx, WRITE);
}

/*
 * rswap_submit_read - Read folio data from the selected KV backend.
 *
 * Called from swap_read_submit().
 */
static void rswap_submit_read(struct swap_io_ctx *ctx)
{
	rswap_submit(ctx, READ);
}

/*
 * rswap_can_merge - Check whether two folios can share a single request.
 *
 * For a KV store each folio is a separate request, so merging is
 * not supported.
 */
static bool rswap_can_merge(struct folio *folio, struct folio *prev_folio,
			    size_t prev_folio_size, int rw)
{
	return false;
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

static int rswap_hashes_alloc(struct swap_info_struct *si)
{
	si->rswap_hashes = kvcalloc(si->max, sizeof(*si->rswap_hashes),
				    GFP_KERNEL);
	if (!si->rswap_hashes)
		return -ENOMEM;
	return 0;
}

static void rswap_hashes_free(struct swap_info_struct *si)
{
	kvfree(si->rswap_hashes);
	si->rswap_hashes = NULL;
}

void rswap_hash_invalidate(struct swap_info_struct *si, unsigned long offset,
			   unsigned int nr_entries)
{
	unsigned long end;

	if (!si->rswap_hashes)
		return;
	if (offset >= si->max)
		return;

	end = offset + min_t(unsigned long, nr_entries, si->max - offset);
	for (; offset < end; offset++) {
		/* Pair with rswap_hash_load() as the swap entry is released. */
		smp_store_release(&si->rswap_hashes[offset].valid, 0);
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

	ret = rswap_hashes_alloc(si);
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
		rswap_hashes_free(si);
		return ret;
	}
	return 0;
}

void rswap_disable(struct swap_info_struct *si)
{
	rswap_hashes_free(si);
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

void rswap_debugfs_add(struct swap_info_struct *si)
{
	char name[32];
	struct dentry *dentry;
	/* Keep a copy of the port in si for debugfs (no UAF). */

	if (!rswap_debugfs_root) {
		rswap_debugfs_root = debugfs_create_dir("rswap", NULL);
		if (IS_ERR_OR_NULL(rswap_debugfs_root))
			return;
		if (rswap_backend)
			rswap_debugfs_backend = (char *)rswap_backend->name;
		debugfs_create_str("backend", 0444, rswap_debugfs_root,
				   &rswap_debugfs_backend);
		debugfs_create_str("endpoint", 0444, rswap_debugfs_root,
				   &rswap_debugfs_endpoint);
	}

	snprintf(name, sizeof(name), "type%d", si->type);
	dentry = debugfs_create_dir(name, rswap_debugfs_root);
	if (IS_ERR_OR_NULL(dentry))
		return;

	/*
	 * Store the port in a heap-allocated variable so debugfs can
	 * safely reference it.  Freed when the dentry is removed.
	 */
	si->rswap_kv_port = kmalloc(sizeof(u32), GFP_KERNEL);
	if (si->rswap_kv_port) {
		*si->rswap_kv_port = rswap_backend_cfg.port;
		debugfs_create_u32("kv_port", 0444, dentry, si->rswap_kv_port);
	}
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
