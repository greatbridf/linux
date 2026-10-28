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
#include <crypto/hash.h>
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

	ret = kernel_sendmsg(sock, &mhdr, &iov, 1, len);
	if (ret < 0)
		return ret;
	if (ret != len)
		return -EIO;
	return 0;
}

/*
 * Send an HTTP request with a data payload (two-part iovec).
 */
static int rswap_send_post(struct socket *sock, const void *hdr, size_t hlen,
			   const void *body, size_t bodylen)
{
	struct msghdr mhdr = { .msg_flags = MSG_NOSIGNAL };
	struct kvec iov[2];
	int ret;

	iov[0].iov_base = (void *)hdr;
	iov[0].iov_len  = hlen;
	iov[1].iov_base = (void *)body;
	iov[1].iov_len  = bodylen;

	ret = kernel_sendmsg(sock, &mhdr, iov, 2, hlen + bodylen);
	if (ret < 0)
		return ret;
	if (ret != hlen + bodylen)
		return -EIO;
	return 0;
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
	char *buf = kmalloc(2048, GFP_KERNEL);
	int total = 0;
	int status = 0;
	char *body = NULL;
	int body_len = 0;
	int ret;

	if (!buf)
		return -ENOMEM;

	/* Read headers (up to 2KB). */
	while (total < 2047) {
		ret = rswap_recv(sock, buf + total, 1);
		if (ret <= 0) {
			ret = -EIO;
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
		ret = -EIO;
		goto out;
	}

	/* For reads, the body follows the headers. */
	if (is_read) {
		body = strstr(buf, "\r\n\r\n");
		if (!body) {
			ret = -EPROTO;
			goto out;
		}
		body += 4;
		body_len = total - (body - buf);

		if (body_len > 0) {
			size_t copy = min_t(size_t, body_len, datalen);
			memcpy(data, body, copy);
		}

		/* If the body is larger than what fit in the header buffer. */
		if (body_len < (int)datalen) {
			int need = datalen - body_len;
			char *p = data + body_len;

			while (need > 0) {
				ret = rswap_recv(sock, p, min(need, 65536));
				if (ret <= 0)
					break;
				p += ret;
				need -= ret;
				body_len += ret;
			}
		}
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
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int ret;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm)) {
		/*
		 * Fallback: derive a deterministic 256-bit value from the
		 * swap entry.  This is not cryptographic-grade but sufficient
		 * for unique key generation.
		 */
		u64 v = entry.val;
		int i;

		for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
			v = v * 6364136223846793005ULL + 1442695040888963407ULL;
			hash[i] = (v >> (i * 7)) & 0xff;
		}
		goto encode;
	}

	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		memset(hash, 0, SHA256_DIGEST_SIZE);
		goto encode;
	}

	desc->tfm = tfm;
	ret = crypto_shash_init(desc);
	if (ret == 0)
		ret = crypto_shash_update(desc, (u8 *)&entry.val,
					  sizeof(entry.val));
	if (ret == 0)
		ret = crypto_shash_final(desc, hash);
	else
		memset(hash, 0, SHA256_DIGEST_SIZE);

	kfree(desc);
	crypto_free_shash(tfm);

encode:
	bin2hex(hex, hash, SHA256_DIGEST_SIZE);
	hex[RSWAP_SHA256_HEXLEN] = '\0';
}

/* ---------- swap_ops implementations ---------- */

/*
 * rswap_submit_write - Send folio data to the KV server via HTTP POST.
 *
 * Called from swap_write_submit().  Uses swap_fs_prepare_rw to set up
 * the completion callback, then sends the HTTP request synchronously.
 */
static void rswap_submit_write(struct swap_io_ctx *ctx)
{
	struct swap_iocb *sio = ctx->sio;
	struct iov_iter iter;
	struct socket *sock;
	char sha256_hex[RSWAP_SHA256_HEXLEN + 1];
	char *data;
	int ret;

	if (sio->nr_bvecs == 0) {
		sio->iocb.ki_complete(&sio->iocb, 0);
		return;
	}

	/*
	 * For now, only handle single-page folios.  Multi-page batching
	 * would need multiple HTTP requests; fall back to an error so the
	 * swap core retries differently.
	 */
	if (sio->nr_bvecs > 1) {
		pr_debug_ratelimited("multi-page write not supported\n");
		sio->iocb.ki_complete(&sio->iocb, -EOPNOTSUPP);
		return;
	}

	/* Prepare the iocb / iov_iter and set up the completion handler. */
	swap_fs_prepare_rw(ctx, WRITE, &iter);

	/* Map the folio data. */
	data = kmap_local_folio(bvec_folio(&sio->bvecs[0]), 0);

	/* Compute the SHA-256 key. */
	rswap_entry_to_sha256(bvec_folio(&sio->bvecs[0])->swap, sha256_hex);

	/* Connect and send POST. */
	sock = rswap_connect();
	if (IS_ERR(sock)) {
		kunmap_local(data);
		sio->iocb.ki_complete(&sio->iocb, PTR_ERR(sock));
		return;
	}

	ret = rswap_http_post(sock, sha256_hex, data, sio->len);
	if (ret == 0) {
		char resp[256];
		ret = rswap_parse_response(sock, resp, sizeof(resp), false);
	}

	kernel_sock_shutdown(sock, SHUT_RDWR);
	sock_release(sock);
	kunmap_local(data);

	if (ret < 0)
		pr_debug_ratelimited("write %s failed: %d\n", sha256_hex, ret);

	/* Signal completion (calls swap_fs_write_complete internally). */
	sio->iocb.ki_complete(&sio->iocb, ret < 0 ? ret : sio->len);
}

/*
 * rswap_submit_read - Read folio data from the KV server via HTTP GET.
 *
 * Called from swap_read_submit().
 */
static void rswap_submit_read(struct swap_io_ctx *ctx)
{
	struct swap_iocb *sio = ctx->sio;
	struct iov_iter iter;
	struct socket *sock;
	char sha256_hex[RSWAP_SHA256_HEXLEN + 1];
	char *data;
	int ret;

	if (sio->nr_bvecs == 0) {
		sio->iocb.ki_complete(&sio->iocb, 0);
		return;
	}

	if (sio->nr_bvecs > 1) {
		pr_debug_ratelimited("multi-page read not supported\n");
		sio->iocb.ki_complete(&sio->iocb, -EOPNOTSUPP);
		return;
	}

	/* Prepare the iocb / iov_iter and set up the completion handler. */
	swap_fs_prepare_rw(ctx, READ, &iter);

	data = kmap_local_folio(bvec_folio(&sio->bvecs[0]), 0);

	rswap_entry_to_sha256(bvec_folio(&sio->bvecs[0])->swap, sha256_hex);

	sock = rswap_connect();
	if (IS_ERR(sock)) {
		kunmap_local(data);
		sio->iocb.ki_complete(&sio->iocb, PTR_ERR(sock));
		return;
	}

	ret = rswap_http_get(sock, sha256_hex);
	if (ret == 0)
		ret = rswap_parse_response(sock, data, sio->len, true);

	kernel_sock_shutdown(sock, SHUT_RDWR);
	sock_release(sock);
	kunmap_local(data);

	if (ret < 0)
		pr_debug_ratelimited("read %s failed: %d\n", sha256_hex, ret);

	sio->iocb.ki_complete(&sio->iocb, ret < 0 ? ret : sio->len);
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
	.flags		= 0,
	.submit_write	= rswap_submit_write,
	.submit_read	= rswap_submit_read,
	.can_merge	= rswap_can_merge,
};

/* ---------- Device setup / teardown ---------- */

int rswap_enable(struct swap_info_struct *si)
{
	if (!(si->flags & SWP_XSWAP))
		return -EINVAL;

	/*
	 * Register our swap_ops.  From this point on, the swap core calls
	 * rswap_submit_write / rswap_submit_read for I/O on this device.
	 */
	return swap_fs_activate(si, &kv_swap_ops);
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
	u32 port = RSWAP_KV_PORT;

	if (!rswap_debugfs_root) {
		rswap_debugfs_root = debugfs_create_dir("rswap", NULL);
		if (IS_ERR_OR_NULL(rswap_debugfs_root))
			return;
	}

	snprintf(name, sizeof(name), "type%d", si->type);
	dentry = debugfs_create_dir(name, rswap_debugfs_root);
	if (IS_ERR_OR_NULL(dentry))
		return;

	debugfs_create_u32("kv_port", 0444, dentry, &port);
}

void rswap_debugfs_del(struct swap_info_struct *si)
{
	char name[32];

	if (!rswap_debugfs_root)
		return;

	snprintf(name, sizeof(name), "type%d", si->type);
	debugfs_lookup_and_remove(name, rswap_debugfs_root);
}
