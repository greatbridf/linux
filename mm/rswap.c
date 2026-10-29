// SPDX-License-Identifier: GPL-2.0
/*
 * mm/rswap.c - Remote Swap via HTTP KV Store
 *
 * rswap implements the swap_ops interface to perform swap I/O through an
 * external HTTP key-value store.  On write-out the kernel sends an HTTP
 * POST with the page data; on read-in it sends an HTTP GET.  The KV store
 * key is the SHA-256 hash of the swap entry value, encoded as a hex
 * string.
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

/* ---------- SHA-256 helpers ---------- */

/*
 * Compute the SHA-256 hash of the swap entry value and encode it as
 * a hexadecimal string.
 *
 * @entry: the swap entry
 * @hex: output buffer, must be at least RSWAP_SHA256_HEXLEN + 1 bytes
 */
static void rswap_entry_to_sha256(swp_entry_t entry, char *hex)
{
	u8 hash[SHA256_DIGEST_SIZE];

	/* Key generation must not change when reclaim-time allocation fails. */
	sha256((const u8 *)&entry.val, sizeof(entry.val), hash);
	bin2hex(hex, hash, SHA256_DIGEST_SIZE);
	hex[RSWAP_SHA256_HEXLEN] = '\0';
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
			swp_entry_t entry = folio->swap;
			struct socket *sock;
			void *mapped;

			entry.val += (bv->bv_offset + offset) >> PAGE_SHIFT;
			rswap_entry_to_sha256(entry, sha256_hex);
			if (rw == WRITE) {
				mapped = kmap_local_folio(folio,
							 bv->bv_offset + offset);
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
				mapped = kmap_local_folio(folio,
							 bv->bv_offset + offset);
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

/* ---------- Device setup / teardown ---------- */

int rswap_enable(struct swap_info_struct *si)
{
	int ret;

	if (!(si->flags & SWP_XSWAP))
		return -EINVAL;

	/*
	 * Register our swap_ops.  From this point on, the swap core calls
	 * rswap_submit_write / rswap_submit_read for I/O on this device.
	 *
	 * swap_fs_activate() returns the result of add_swap_extent(), which
	 * returns 0 (merge) or 1 (new extent) on success.  Map both to 0 so
	 * the caller can use the conventional if (ret < 0) error check.
	 */
	ret = swap_fs_activate(si, &kv_swap_ops);
	if (ret < 0)
		return ret;
	return 0;
}

void rswap_disable(struct swap_info_struct *si)
{
	/* Nothing to do for now. */
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
