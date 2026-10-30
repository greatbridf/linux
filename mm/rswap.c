// SPDX-License-Identifier: GPL-2.0
/*
 * mm/rswap.c - Remote Swap via HTTP KV Store
 *
 * rswap implements the swap_ops interface to perform swap I/O through an
 * external HTTP key-value store.  On write-out the kernel sends an HTTP
 * POST with the page data; on read-in it sends an HTTP GET.  The KV store
 * key is a SHA-256 digest, encoded as a hex string.
 *
 * == Keys ==
 *
 * The digest is supplied by user space, which knows what a page holds and
 * attaches the digest to it through /proc/sys/vm/rswap/attach.  The digest
 * is kept in page_ext until writeout, then copied into a per-device table
 * indexed by swap offset.  Swapin uses that table entry as the KV key, so
 * the key does not depend on the page remaining in the swap cache.  Pages
 * with no attached digest fall back to a digest of the swap entry.
 *
 * == Data flow ==
 *
 * swap-out (reclaim):
 *   swap_writeout() -> swap_add_folio() -> swap_write_submit()
 *   -> rswap_submit_write() -> HTTP POST /v1/folios/<sha256>/write
 *
 * swap-in (page fault):
 *   swap_read_folio() -> swap_add_folio() -> swap_read_submit()
 *   -> rswap_submit_read()  -> HTTP GET  /v1/folios/<sha256>/read
 *
 * The KV server (tools/mm/kvswap_server.c) stores each page as a file
 * whose name is the SHA-256 hex string.
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
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/net.h>
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
#include <net/sock.h>

#include "swap.h"
#include "rswap.h"

/* ---------- Configuration ---------- */

#define RSWAP_KV_HOST		"127.0.0.1"
#define RSWAP_KV_PORT		6789
#define RSWAP_SHA256_HEXLEN	64	/* SHA-256 -> 64 hex chars */

/* ---------- Socket helpers ---------- */

/*
 * Create a TCP socket and connect to the KV server.
 * Returns the socket struct, or ERR_PTR on error.
 */
static struct socket *rswap_connect(void)
{
	struct socket *sock;
	struct sockaddr_in sin;
	int ret;

	ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP,
			       &sock);
	if (ret < 0) {
		pr_err_ratelimited("sock_create_kern failed: %d\n", ret);
		return ERR_PTR(ret);
	}

	sock_set_sndtimeo(sock->sk, 1);
	WRITE_ONCE(sock->sk->sk_rcvtimeo, HZ);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(RSWAP_KV_PORT);
	if (in4_pton(RSWAP_KV_HOST, -1, (u8 *)&sin.sin_addr.s_addr, -1, NULL) == 0) {
		pr_err("bad KV host address: %s\n", RSWAP_KV_HOST);
		sock_release(sock);
		return ERR_PTR(-EINVAL);
	}

	ret = kernel_connect(sock, (struct sockaddr_unsized *)&sin, sizeof(sin), 0);
	if (ret < 0) {
		pr_err_ratelimited("kernel_connect to %s:%d failed: %d\n",
				   RSWAP_KV_HOST, RSWAP_KV_PORT, ret);
		sock_release(sock);
		return ERR_PTR(ret);
	}

	return sock;
}

/*
 * Send a complete HTTP request message.
 */
static int rswap_send_request(struct socket *sock, const void *msg, size_t len)
{
	struct msghdr mhdr = { .msg_flags = MSG_NOSIGNAL };
	struct kvec iov = { .iov_base = (void *)msg, .iov_len = len };
	int ret;

	while (iov.iov_len) {
		ret = kernel_sendmsg(sock, &mhdr, &iov, 1, iov.iov_len);
		if (ret <= 0)
			return ret ? ret : -EIO;
		iov.iov_base = (char *)iov.iov_base + ret;
		iov.iov_len -= ret;
	}
	return 0;
}

/*
 * Send an HTTP request with a data payload (two-part iovec).
 */
static int rswap_send_post(struct socket *sock, const void *hdr, size_t hlen,
			   const void *body, size_t bodylen)
{
	int ret;

	ret = rswap_send_request(sock, hdr, hlen);
	if (ret < 0)
		return ret;
	return rswap_send_request(sock, body, bodylen);
}

/* Receive data into a buffer. */
static int rswap_recv(struct socket *sock, char *buf, int len)
{
	struct msghdr mhdr = { .msg_flags = MSG_NOSIGNAL };
	struct kvec iov = { .iov_base = buf, .iov_len = len };
	int ret;

	ret = kernel_recvmsg(sock, &mhdr, &iov, 1, len, 0);
	if (ret < 0)
		return ret;
	return ret;
}

/* ---------- HTTP request/response helpers ---------- */

/*
 * Build and send an HTTP GET request.
 */
static int rswap_http_get(struct socket *sock, const char *sha256_hex)
{
	char req[256];
	int ret;

	ret = snprintf(req, sizeof(req),
		       "GET /v1/folios/%s/read HTTP/1.0\r\n"
		       "Host: " RSWAP_KV_HOST ":%d\r\n"
		       "Connection: close\r\n"
		       "\r\n",
		       sha256_hex, RSWAP_KV_PORT);
	if (ret >= (int)sizeof(req))
		return -ENOSPC;

	return rswap_send_request(sock, req, ret);
}

/*
 * Build and send an HTTP POST request with folio data.
 */
static int rswap_http_post(struct socket *sock, const char *sha256_hex,
			   const void *data, size_t datalen)
{
	char hdr[512];
	int hlen;

	hlen = snprintf(hdr, sizeof(hdr),
			"POST /v1/folios/%s/write HTTP/1.0\r\n"
			"Host: " RSWAP_KV_HOST ":%d\r\n"
			"Content-Length: %zu\r\n"
			"Content-Type: application/octet-stream\r\n"
			"Connection: close\r\n"
			"\r\n",
			sha256_hex, RSWAP_KV_PORT, datalen);
	if (hlen >= (int)sizeof(hdr))
		return -ENOSPC;

	return rswap_send_post(sock, hdr, hlen, data, datalen);
}

/*
 * Parse the HTTP response.  Extracts the status code and,
 * for GET requests, copies the body into @data.
 *
 * Returns 0 on success (HTTP 200), -errno on failure.
 */
static int rswap_parse_response(struct socket *sock,
				char *data, size_t datalen, bool is_read)
{
	/*
	 * Heap-allocate the header buffer to keep stack usage under the
	 * 2048-byte warning threshold.  Our responses are tiny.
	 */
	char *buf = kmalloc(2048, GFP_NOIO);
	int total = 0;
	int status = 0;
	char *line;
	size_t content_length = 0;
	size_t received = 0;
	bool have_length = false;
	int ret;

	if (!buf)
		return -ENOMEM;

	/* Read headers (up to 2KB). */
	while (total < 2047) {
		ret = rswap_recv(sock, buf + total, 1);
		if (ret <= 0) {
			ret = ret ? ret : -EIO;
			goto out;
		}
		total += ret;
		buf[total] = '\0';

		/* End of headers: \r\n\r\n */
		if (total >= 4 &&
		    memcmp(buf + total - 4, "\r\n\r\n", 4) == 0)
			break;
	}
	if (total >= 2047) {
		ret = -ENOSPC;
		goto out;
	}

	/* Parse "HTTP/1.x NNN ..." */
	if (sscanf(buf, "HTTP/%*d.%*d %d", &status) != 1) {
		ret = -EPROTO;
		goto out;
	}
	if (status != 200) {
		ret = status == 404 ? -ENOENT : -EIO;
		goto out;
	}

	line = strstr(buf, "\r\n");
	while (line) {
		char *next;

		line += 2;
		next = strstr(line, "\r\n");
		if (!next || next == line)
			break;
		*next = '\0';
		if (!strncasecmp(line, "Content-Length:", 15)) {
			char *value = skip_spaces(line + 15);

			if (have_length || kstrtoul(value, 10, &content_length)) {
				ret = -EPROTO;
				goto out;
			}
			have_length = true;
		} else if (!strncasecmp(line, "Transfer-Encoding:", 18)) {
			ret = -EPROTO;
			goto out;
		}
		line = next;
	}
	if (!have_length || content_length != (is_read ? datalen : 0)) {
		ret = -EPROTO;
		goto out;
	}
	while (received < content_length) {
		ret = rswap_recv(sock, data + received,
				 min_t(size_t, content_length - received, 65536));
		if (ret <= 0) {
			ret = ret ? ret : -EIO;
			goto out;
		}
		received += ret;
	}

	ret = 0;
out:
	kfree(buf);
	return ret;
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
 * On write, use the digest attached to @page or fall back to a digest of
 * @entry, then persist it in the device table.  On read, use the persisted
 * digest so the key does not depend on the page still being in swap cache.
 */
static int rswap_page_key(struct swap_info_struct *si, struct page *page,
			  swp_entry_t entry, int rw, char *hex)
{
	u8 hash[SHA256_DIGEST_SIZE];
	int ret;

	if (rw == WRITE) {
		if (!rswap_page_get_hash(page, hash))
			sha256((const u8 *)&entry.val, sizeof(entry.val), hash);
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
 * Submit each base page synchronously and complete the whole swap request.
 */
static void rswap_submit(struct swap_io_ctx *ctx, int rw)
{
	struct swap_iocb *sio = ctx->sio;
	struct iov_iter iter;
	char sha256_hex[RSWAP_SHA256_HEXLEN + 1];
	char *data = NULL;
	int ret = 0;
	int i;
	unsigned int noio_flags;

	noio_flags = memalloc_noio_save();
	swap_fs_prepare_rw(ctx, rw, &iter);
	data = kmalloc(PAGE_SIZE, GFP_NOIO);
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
			struct socket *sock;
			void *mapped;

			ret = rswap_page_key(si, page, entry, rw, sha256_hex);
			if (ret)
				goto io_error;
			if (rw == WRITE) {
				mapped = kmap_local_page(page);
				memcpy(data, mapped, PAGE_SIZE);
				kunmap_local(mapped);
			}
			sock = rswap_connect();
			if (IS_ERR(sock)) {
				ret = PTR_ERR(sock);
				goto io_error;
			}
			if (rw == WRITE)
				ret = rswap_http_post(sock, sha256_hex,
						     data, PAGE_SIZE);
			else
				ret = rswap_http_get(sock, sha256_hex);
			if (!ret)
				ret = rswap_parse_response(sock, data,
							   PAGE_SIZE, rw == READ);
			kernel_sock_shutdown(sock, SHUT_RDWR);
			sock_release(sock);
			if (ret)
				goto io_error;
			if (rw == READ) {
				mapped = kmap_local_page(page);
				memcpy(mapped, data, PAGE_SIZE);
				kunmap_local(mapped);
			}
			continue;
io_error:
			pr_err_ratelimited("%s type %u offset %lu failed: %d\n",
					   rw == WRITE ? "write" : "read",
					   swp_type(entry), swp_offset(entry), ret);
			goto out;
		}
	}
out:
	kfree(data);
	memalloc_noio_restore(noio_flags);
	sio->iocb.ki_complete(&sio->iocb, ret < 0 ? ret : sio->len);
}

static void rswap_submit_write(struct swap_io_ctx *ctx)
{
	rswap_submit(ctx, WRITE);
}

/*
 * rswap_submit_read - Read folio data from the KV server via HTTP GET.
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
 * For the KV store each folio is a separate HTTP request, so merging is
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
	if (!write || *ppos)
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

void rswap_debugfs_add(struct swap_info_struct *si)
{
	char name[32];
	struct dentry *dentry;
	/* Keep a copy of the port in si for debugfs (no UAF). */

	if (!rswap_debugfs_root) {
		rswap_debugfs_root = debugfs_create_dir("rswap", NULL);
		if (IS_ERR_OR_NULL(rswap_debugfs_root))
			return;
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
		*si->rswap_kv_port = RSWAP_KV_PORT;
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
