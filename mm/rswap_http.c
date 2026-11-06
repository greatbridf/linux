// SPDX-License-Identifier: GPL-2.0
/*
 * mm/rswap_http.c - rswap KV backend speaking HTTP to kvswap_server
 *
 * One base page is one HTTP/1.0 request:
 *
 *   write:  POST /v1/folios/<key>/write   body = page data
 *   read:   GET  /v1/folios/<key>/read
 *
 * <key> is the hex form of the digest supplied for the page: 96 characters,
 * RSWAP_KV_KEY_LEN bytes with the NUL (see mm/rswap_backend.h).  The server
 * (tools/mm/kvswap_server.c) stores each page as a file named by that key.
 */

#define pr_fmt(fmt) "rswap: " fmt

#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kstrtox.h>
#include <linux/net.h>

#include "rswap_backend.h"

#define RSWAP_HTTP_DEFAULT_HOST		"127.0.0.1"
#define RSWAP_HTTP_DEFAULT_PORT		6789
#define RSWAP_HTTP_CONNECT_TIMEOUT_MS	1000
#define RSWAP_HTTP_SEND_TIMEOUT_MS	20
#define RSWAP_HTTP_RECV_TIMEOUT_MS	1000
#define RSWAP_HTTP_MAX_HEADER		2048

static struct {
	char		host[RSWAP_KV_HOST_LEN];
	u16		port;
	unsigned int	send_timeout_ms;
	unsigned int	recv_timeout_ms;
} rswap_http;

/*
 * Budget for one HTTP request: one connect, one send and two receives, one for
 * the response headers and one for the body.  A peer cannot stretch a request
 * much past this, it can only add the single operation that is in flight.
 */
static unsigned long rswap_http_deadline(void)
{
	return rswap_sock_deadline(RSWAP_HTTP_CONNECT_TIMEOUT_MS +
				   rswap_http.send_timeout_ms +
				   2 * rswap_http.recv_timeout_ms);
}

static struct socket *rswap_http_open(void)
{
	return rswap_sock_connect(rswap_http.host, rswap_http.port,
				  RSWAP_HTTP_CONNECT_TIMEOUT_MS,
				  rswap_http.send_timeout_ms,
				  rswap_http.recv_timeout_ms);
}

/* Build and send an HTTP GET request. */
static int rswap_http_get(struct socket *sock, const char *key,
			  unsigned long deadline)
{
	char req[256];
	int ret;

	ret = snprintf(req, sizeof(req),
		       "GET /v1/folios/%s/read HTTP/1.0\r\n"
		       "Host: %s:%u\r\n"
		       "Connection: close\r\n"
		       "\r\n",
		       key, rswap_http.host, rswap_http.port);
	if (ret >= (int)sizeof(req))
		return -ENOSPC;

	return rswap_sock_send(sock, req, ret, deadline);
}

/* Build and send an HTTP POST request carrying the page image @page. */
static int rswap_http_post(struct socket *sock, const char *key,
			   struct page *page, size_t len,
			   unsigned long deadline)
{
	char hdr[512];
	int hlen;
	int ret;

	hlen = snprintf(hdr, sizeof(hdr),
			"POST /v1/folios/%s/write HTTP/1.0\r\n"
			"Host: %s:%u\r\n"
			"Content-Length: %zu\r\n"
			"Content-Type: application/octet-stream\r\n"
			"Connection: close\r\n"
			"\r\n",
			key, rswap_http.host, rswap_http.port, len);
	if (hlen >= (int)sizeof(hdr))
		return -ENOSPC;

	ret = rswap_sock_send(sock, hdr, hlen, deadline);
	if (ret)
		return ret;
	return rswap_sock_send_page(sock, page, len, deadline);
}

/* ---------- Response parsing ---------- */

/*
 * Offset just past the "\r\n\r\n" that ends the header block, or 0 while it
 * has not arrived yet.  @scanned carries the part already searched, so a
 * terminator that is split across two receives is still found.
 */
static size_t rswap_http_header_end(const char *buf, size_t total,
				    size_t *scanned)
{
	size_t i = *scanned > 3 ? *scanned - 3 : 0;

	for (; i + 4 <= total; i++) {
		if (!memcmp(buf + i, "\r\n\r\n", 4)) {
			*scanned = i + 4;
			return i + 4;
		}
	}
	*scanned = total;
	return 0;
}

/*
 * Parse the HTTP response.  Extracts the status code and, for GET requests,
 * reads the body straight into the page image @page.
 *
 * Returns 0 on success (HTTP 200), -errno on failure.
 */
static int rswap_http_parse_response(struct socket *sock, struct page *page,
				     size_t len, bool is_read,
				     unsigned long deadline)
{
	/*
	 * Heap-allocate the header buffer to keep stack usage under the
	 * 2048-byte warning threshold.  Our responses are tiny.
	 */
	char *buf = kmalloc(RSWAP_HTTP_MAX_HEADER, GFP_NOIO);
	size_t scanned = 0;
	size_t total = 0;
	size_t hdr_end = 0;
	size_t have;
	size_t content_length = 0;
	bool have_length = false;
	char *line, *end;
	int status = 0;
	int ret;

	if (!buf)
		return -ENOMEM;

	/*
	 * Read the header block in as few calls as the peer allows: one receive
	 * returns whatever has arrived, so a normal response needs one.  The
	 * last byte of the buffer stays reserved for the NUL.
	 */
	while (total < RSWAP_HTTP_MAX_HEADER - 1) {
		if (rswap_sock_expired(deadline)) {
			ret = -ETIMEDOUT;
			goto out;
		}
		ret = rswap_sock_recv(sock, buf + total,
				      RSWAP_HTTP_MAX_HEADER - 1 - total);
		if (ret <= 0) {
			ret = ret ? ret : -EIO;
			goto out;
		}
		total += ret;
		buf[total] = '\0';
		hdr_end = rswap_http_header_end(buf, total, &scanned);
		if (hdr_end)
			break;
	}
	if (!hdr_end) {
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

	/*
	 * The header lines end with the empty line of the terminator; drop that
	 * empty line and NUL-terminate the block for the scan below.
	 */
	end = buf + hdr_end - 2;
	*end = '\0';
	line = buf;
	while (line < end) {
		char *next = line;

		while (next + 2 <= end &&
		       (next[0] != '\r' || next[1] != '\n'))
			next++;
		if (next + 2 > end)
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
		line = next + 2;
	}
	if (!have_length || content_length != (is_read ? len : 0)) {
		ret = -EPROTO;
		goto out;
	}
	if (!is_read) {
		ret = 0;
		goto out;
	}

	/*
	 * A receive returns whatever has arrived, so the first bytes of the body
	 * may already be in the header buffer.  They belong at the start of the
	 * page, and only the rest is still on the socket.  The header buffer is
	 * far smaller than a page, so it can never hold the whole body.
	 */
	have = total - hdr_end;
	if (have) {
		void *addr = kmap_local_page(page);

		memcpy(addr, buf + hdr_end, have);
		kunmap_local(addr);
	}
	ret = rswap_sock_recv_page(sock, page, have, content_length - have,
				   deadline);
out:
	kfree(buf);
	return ret;
}

/* ---------- Backend operations ---------- */

/* Reject a batch whose keys are not the full digest strings the core made. */
static int rswap_http_validate(struct rswap_kv_page *pages, unsigned int nr,
			       size_t len)
{
	unsigned int i;

	if (!nr || nr > RSWAP_BATCH_MAX || len != PAGE_SIZE)
		return -EINVAL;
	for (i = 0; i < nr; i++) {
		if (strlen(pages[i].key) + 1 != RSWAP_KV_KEY_LEN)
			return -EINVAL;
	}
	return 0;
}

/*
 * HTTP/1.0 carries exactly one object per request, so a batch is a plain
 * sequence of requests.
 */
static int rswap_http_store(struct rswap_kv_page *pages, unsigned int nr,
			    size_t len)
{
	unsigned int i;
	int ret;

	ret = rswap_http_validate(pages, nr, len);
	if (ret)
		return ret;

	for (i = 0; i < nr; i++) {
		struct socket *sock;
		unsigned long deadline = rswap_http_deadline();

		sock = rswap_http_open();
		if (IS_ERR(sock))
			return PTR_ERR(sock);

		ret = rswap_http_post(sock, pages[i].key, pages[i].page, len,
				      deadline);
		if (!ret)
			ret = rswap_http_parse_response(sock, NULL, len, false,
							deadline);
		rswap_sock_close(sock);
		if (ret)
			return ret;
	}
	return 0;
}

static int rswap_http_load(struct rswap_kv_page *pages, unsigned int nr,
			   size_t len)
{
	unsigned int i;
	int ret;

	ret = rswap_http_validate(pages, nr, len);
	if (ret)
		return ret;

	for (i = 0; i < nr; i++) {
		struct socket *sock;
		unsigned long deadline = rswap_http_deadline();

		sock = rswap_http_open();
		if (IS_ERR(sock))
			return PTR_ERR(sock);

		ret = rswap_http_get(sock, pages[i].key, deadline);
		if (!ret)
			ret = rswap_http_parse_response(sock, pages[i].page, len,
							true, deadline);
		rswap_sock_close(sock);
		if (ret)
			return ret;
	}
	return 0;
}

/* ---------- Backend registration ---------- */

static int rswap_http_init(const struct rswap_kv_config *cfg)
{
	if (strscpy(rswap_http.host, cfg->host, sizeof(rswap_http.host)) < 0)
		return -EINVAL;

	rswap_http.port = cfg->port;
	rswap_http.send_timeout_ms = cfg->send_timeout_ms;
	rswap_http.recv_timeout_ms = cfg->recv_timeout_ms;
	return 0;
}

const struct rswap_backend rswap_http_backend = {
	.name			= "http",
	.description		= "HTTP/1.0 key-value store (kvswap_server)",
	.default_host		= RSWAP_HTTP_DEFAULT_HOST,
	.default_port		= RSWAP_HTTP_DEFAULT_PORT,
	.default_send_timeout_ms = RSWAP_HTTP_SEND_TIMEOUT_MS,
	.default_recv_timeout_ms = RSWAP_HTTP_RECV_TIMEOUT_MS,
	.init			= rswap_http_init,
	.store			= rswap_http_store,
	.load			= rswap_http_load,
};
