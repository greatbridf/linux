// SPDX-License-Identifier: GPL-2.0
/*
 * mm/rswap_redis.c - rswap KV backend speaking RESP to a Redis server
 *
 * Keys are the same 64 character lowercase SHA-256 hex strings the other
 * backends use, so a Redis dump can be audited directly against the digests
 * user space attached.  Values are raw base page images.
 *
 * One batch of up to RSWAP_BATCH_MAX pages is one pipelined write:
 *
 *   write:  (SET <key> <page bytes>)+
 *   read:   (GET <key>)+
 *
 * Connections are pooled and reused, with AUTH and SELECT sent once when a
 * connection is opened.  That matters more than the batch size: a fresh
 * connection pays a handshake plus TCP slow start, which for one batch of 128
 * KiB over a 12 ms path costs about 90 ms, against about 15 ms for the same
 * batch on an established connection.  Nothing is cached across a *failed*
 * connection: a transport error drops the socket, and the batch is retried
 * once on a fresh one, which is safe because SET and GET are idempotent.
 *
 * Swap I/O runs on many CPUs at once, so the pool hands out one connection per
 * caller instead of holding a lock across the I/O.
 */

#define pr_fmt(fmt) "rswap: " fmt

#include <linux/bvec.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <linux/semaphore.h>
#include <linux/string.h>
#include <linux/kstrtox.h>
#include <linux/net.h>

#include "rswap_backend.h"

#define RSWAP_REDIS_DEFAULT_HOST	"127.0.0.1"
#define RSWAP_REDIS_DEFAULT_PORT	6379
#define RSWAP_REDIS_SEND_TIMEOUT_MS	10000
#define RSWAP_REDIS_RECV_TIMEOUT_MS	10000
/* Upper bound for one command: array and bulk headers plus a 64 digit key. */
#define RSWAP_REDIS_CMD_SIZE		(RSWAP_KV_KEY_LEN + 32)
/* Status, error and bulk length lines are all tiny. */
#define RSWAP_REDIS_MAX_LINE		256
/* Cached connections; more concurrent batches than this fall back to new. */
#define RSWAP_REDIS_POOL_MAX		8
/* A request consists of header, len and data at most. */
#define RSWAP_CMD_BVECS			3 * RSWAP_BATCH_MAX
/* A small buffer for common use just in case. */
#define RSWAP_CMD_BUF_SIZE		256

static struct {
	char		host[RSWAP_KV_HOST_LEN];
	u16		port;
	char		user[RSWAP_KV_HOST_LEN];
	char		password[128];
	unsigned int	db;
	unsigned int	send_timeout_ms;
	unsigned int	recv_timeout_ms;
} rswap_redis;

/* ---------- RESP wire format ---------- */

enum {
	RSWAP_CMD_AUTH,
	RSWAP_CMD_GET,
	RSWAP_CMD_SET,

	RSWAP_CMD_ARG_2,
	RSWAP_CMD_ARG_3,

	RSWAP_CMD_BULK_2,
	RSWAP_CMD_BULK_3,
	RSWAP_CMD_BULK_PAGE_SIZE,

	// and necessary items...

	NR_RSWAP_CMD_PARTS,
};

// initialize in __init, alloc one folio, store strings and then fill them.
static struct bio_vec rswap_common_part_bios[NR_RSWAP_CMD_PARTS];

/* Builder for a run of pipelined commands inside one write buffer. */
struct rswap_redis_cmd {
	size_t		size;
	size_t		len;

	struct bio_vec	bvecs[RSWAP_CMD_BVECS];
	char		buf[RSWAP_CMD_BUF_SIZE];
};

static struct rswap_redis_cmd rswap_redis_cmd_alloc(void)
{
	// alloc from a slab or mempool
}

/* Append a "*<argc>\r\n" array header. */
static int rswap_redis_add_array(struct rswap_redis_cmd *cmd, unsigned int argc)
{
	char prefix[16];
	int len;

	len = snprintf(prefix, sizeof(prefix), "*%u\r\n", argc);
	if (len < 0 || cmd->len + len > cmd->size)
		return -ENOSPC;
	memcpy(cmd->buf + cmd->len, prefix, len);
	cmd->len += len;
	return 0;
}

/* Append the "$<len>\r\n" prefix of a bulk string, without its payload. */
static int rswap_redis_add_bulk_header(struct rswap_redis_cmd *cmd, size_t len)
{
	char prefix[24];
	int plen;

	plen = snprintf(prefix, sizeof(prefix), "$%zu\r\n", len);
	if (plen < 0 || cmd->len + plen + 2 > cmd->size)
		return -ENOSPC;
	memcpy(cmd->buf + cmd->len, prefix, plen);
	cmd->len += plen;
	return 0;
}

/* Append raw bytes, used for bulk payloads that are already in memory. */
static int rswap_redis_add_raw(struct rswap_redis_cmd *cmd, const void *data,
			       size_t len)
{
	if (cmd->len + len > cmd->size)
		return -ENOSPC;
	memcpy(cmd->buf + cmd->len, data, len);
	cmd->len += len;
	return 0;
}

/* Append a complete bulk string argument. */
static int rswap_redis_add_bulk(struct rswap_redis_cmd *cmd, const void *arg,
				size_t len)
{
	int ret;

	ret = rswap_redis_add_bulk_header(cmd, len);
	if (ret)
		return ret;
	if (cmd->len + len + 2 > cmd->size)
		return -ENOSPC;
	memcpy(cmd->buf + cmd->len, arg, len);
	cmd->len += len;
	memcpy(cmd->buf + cmd->len, "\r\n", 2);
	cmd->len += 2;
	return 0;
}

/* Read one CRLF terminated line, without the terminator. */
static int rswap_redis_read_line(struct socket *sock, char *line, size_t size)
{
	size_t len = 0;
	int ret;

	for (;;) {
		if (len + 2 > size)
			return -ENOSPC;
		ret = rswap_sock_recv(sock, line + len, 1);
		if (ret <= 0)
			return ret ? ret : -ECONNRESET;
		if (line[len] == '\n') {
			if (!len || line[len - 1] != '\r')
				return -EPROTO;
			line[len - 1] = '\0';
			return 0;
		}
		len++;
	}
}

/* Map a "-ERR ..." reply to an errno. */
static int rswap_redis_errno(const char *line)
{
	const char *error = line + 1;

	if (!strncmp(error, "NOAUTH", 6) || !strncmp(error, "WRONGPASS", 9) ||
	    !strncmp(error, "NOPERM", 6))
		return -EACCES;
	return -EIO;
}

/* Read a simple status reply and require @expected ("OK", ...). */
static int rswap_redis_status(struct socket *sock, const char *expected)
{
	char line[RSWAP_REDIS_MAX_LINE];
	int ret;

	ret = rswap_redis_read_line(sock, line, sizeof(line));
	if (ret)
		return ret;
	if (line[0] == '-')
		return rswap_redis_errno(line);
	if (line[0] != '+')
		return -EPROTO;
	if (strcmp(line + 1, expected))
		return -EPROTO;
	return 0;
}

/* Read a bulk reply into @data, which must be exactly @len bytes long. */
static int rswap_redis_read_bulk(struct socket *sock, void *data, size_t len)
{
	char line[RSWAP_REDIS_MAX_LINE];
	char trailer[2];
	size_t received = 0;
	long value_len;
	int ret;

	ret = rswap_redis_read_line(sock, line, sizeof(line));
	if (ret)
		return ret;
	if (line[0] == '-')
		return rswap_redis_errno(line);
	if (line[0] != '$')
		return -EPROTO;
	if (kstrtol(line + 1, 10, &value_len))
		return -EPROTO;
	if (value_len < 0)
		return -ENOENT;		/* $-1: no such key */
	/*
	 * A page is always read back whole: a different length means the
	 * stored object is not the page we are looking for.
	 */
	if ((size_t)value_len != len)
		return -EMSGSIZE;

	while (received < len) {
		ret = rswap_sock_recv(sock, (char *)data + received,
				      min_t(size_t, len - received, 65536));
		if (ret <= 0)
			return ret ? ret : -ECONNRESET;
		received += ret;
	}

	/* Trailing CRLF of the bulk string. */
	received = 0;
	while (received < sizeof(trailer)) {
		ret = rswap_sock_recv(sock, trailer + received,
				      sizeof(trailer) - received);
		if (ret <= 0)
			return ret ? ret : -ECONNRESET;
		received += ret;
	}
	if (trailer[0] != '\r' || trailer[1] != '\n')
		return -EPROTO;
	return 0;
}

/*
 * Queue AUTH and SELECT.  Returns the number of status replies they add, in
 * order, in @replies.
 */
static int rswap_redis_queue_preamble(struct rswap_redis_cmd *cmd,
				      unsigned int *replies)
{
	int ret;

	*replies = 0;
	if (rswap_redis.password[0]) {
		ret = rswap_redis_add_array(cmd, rswap_redis.user[0] ? 3 : 2);
		if (!ret)
			ret = rswap_redis_add_bulk(cmd, "AUTH", 4);
		if (!ret && rswap_redis.user[0])
			ret = rswap_redis_add_bulk(cmd, rswap_redis.user,
						   strlen(rswap_redis.user));
		if (!ret)
			ret = rswap_redis_add_bulk(cmd, rswap_redis.password,
						   strlen(rswap_redis.password));
		if (ret)
			return ret;
		(*replies)++;
	}

	if (rswap_redis.db) {
		char db[16];
		int dblen;

		dblen = snprintf(db, sizeof(db), "%u", rswap_redis.db);
		if (dblen < 0)
			return -EINVAL;
		ret = rswap_redis_add_array(cmd, 2);
		if (!ret)
			ret = rswap_redis_add_bulk(cmd, "SELECT", 6);
		if (!ret)
			ret = rswap_redis_add_bulk(cmd, db, dblen);
		if (ret)
			return ret;
		(*replies)++;
	}

	return 0;
}

/* ---------- Connection pool ---------- */

struct rswap_redis_conn {
	struct socket	*sock;
	bool		busy;
};

static DEFINE_MUTEX(rswap_redis_pool_lock);
static DEFINE_SEMAPHORE(rswap_redis_pool_sem, RSWAP_REDIS_POOL_MAX);
static struct rswap_redis_conn rswap_redis_pool[RSWAP_REDIS_POOL_MAX];

static atomic64_t rswap_redis_connects;
static atomic64_t rswap_redis_reuses;
static atomic64_t rswap_redis_dropped;
static atomic64_t rswap_redis_retries;

/* Errors that mean the connection is unusable, not that the key is absent. */
static bool rswap_redis_transport_error(int err)
{
	return err && err != -ENOENT && err != -EMSGSIZE;
}

static void rswap_redis_drop(struct rswap_redis_conn *conn)
{
	if (!conn->sock)
		return;
	rswap_sock_close(conn->sock);
	conn->sock = NULL;
	atomic64_inc(&rswap_redis_dropped);
}

/* Open a connection if @conn has none, and authenticate it. */
static int rswap_redis_ensure(struct rswap_redis_conn *conn)
{
	struct rswap_redis_cmd cmd;
	/* Holds AUTH (user + secret) and SELECT, far below the limits below. */
	char buf[512];
	unsigned int replies;
	unsigned int i;
	int ret;

	if (conn->sock) {
		if (rswap_sock_alive(conn->sock)) {
			atomic64_inc(&rswap_redis_reuses);
			return 0;
		}
		rswap_redis_drop(conn);
	}

	conn->sock = rswap_sock_connect(rswap_redis.host, rswap_redis.port,
					rswap_redis.send_timeout_ms,
					rswap_redis.recv_timeout_ms);
	if (IS_ERR(conn->sock)) {
		ret = PTR_ERR(conn->sock);
		conn->sock = NULL;
		return ret;
	}
	atomic64_inc(&rswap_redis_connects);

	cmd.buf = buf;
	cmd.size = sizeof(buf);
	cmd.len = 0;
	ret = rswap_redis_queue_preamble(&cmd, &replies);
	if (!ret && replies) {
		ret = rswap_sock_send(conn->sock, cmd.buf, cmd.len);
		for (i = 0; !ret && i < replies; i++)
			ret = rswap_redis_status(conn->sock, "OK");
	}
	if (ret)
		rswap_redis_drop(conn);
	return ret;
}

static struct rswap_redis_conn *rswap_redis_conn_get(void)
{
	struct rswap_redis_conn *conn = NULL;
	unsigned int i;

	down(&rswap_redis_pool_sem);
	mutex_lock(&rswap_redis_pool_lock);
	for (i = 0; i < RSWAP_REDIS_POOL_MAX; i++) {
		if (!rswap_redis_pool[i].busy) {
			rswap_redis_pool[i].busy = true;
			conn = &rswap_redis_pool[i];
			break;
		}
	}
	mutex_unlock(&rswap_redis_pool_lock);

	if (WARN_ON_ONCE(!conn)) {
		up(&rswap_redis_pool_sem);
		return NULL;
	}
	return conn;
}

static void rswap_redis_conn_put(struct rswap_redis_conn *conn)
{
	mutex_lock(&rswap_redis_pool_lock);
	conn->busy = false;
	mutex_unlock(&rswap_redis_pool_lock);
	up(&rswap_redis_pool_sem);
}

/* ---------- Backend operations ---------- */

static int rswap_redis_do_store(struct rswap_redis_conn *conn,
				struct rswap_kv_page *pages, unsigned int nr,
				size_t len)
{
	struct rswap_redis_cmd cmd;
	char *request;
	void *data;
	unsigned int i;
	int ret = 0;

	/* Command headers plus every payload. */
	request = kvmalloc(nr * (RSWAP_REDIS_CMD_SIZE + len + 2), GFP_NOIO);
	if (!request)
		return -ENOMEM;

	cmd.buf = request;
	cmd.size = nr * (RSWAP_REDIS_CMD_SIZE + len + 2);
	cmd.len = 0;

	for (i = 0; !ret && i < nr; i++) {
		ret = rswap_redis_add_array(&cmd, 3);
		if (!ret)
			ret = rswap_redis_add_bulk(&cmd, "SET", 3);
		if (!ret)
			ret = rswap_redis_add_bulk(&cmd, pages[i].key,
						   strlen(pages[i].key));
		if (!ret)
			ret = rswap_redis_add_bulk_header(&cmd, len);
		/* A bulk payload must follow its own header directly. */
		if (!ret) {
			data = kmap_local_page(pages[i].page);
			ret = rswap_redis_add_raw(&cmd, data, len);
			kunmap_local(data);
		}
		if (!ret)
			ret = rswap_redis_add_raw(&cmd, "\r\n", 2);
	}
	if (ret)
		goto out_free;

	ret = rswap_sock_send(conn->sock, request, cmd.len);
	for (i = 0; !ret && i < nr; i++)
		ret = rswap_redis_status(conn->sock, "OK");

out_free:
	kvfree(request);
	if (rswap_redis_transport_error(ret))
		rswap_redis_drop(conn);
	return ret;
}

static int rswap_redis_do_load(struct rswap_redis_conn *conn,
			       struct rswap_kv_page *pages, unsigned int nr,
			       size_t len)
{
	struct rswap_redis_cmd cmd;
	void *data;
	unsigned int i;
	int ret = 0;

	for (i = 0; !ret && i < nr; i++) {
		ret = rswap_redis_add_array(&cmd, 2);
		if (!ret)
			ret = rswap_redis_add_bulk(&cmd, "GET", 3);
		if (!ret)
			ret = rswap_redis_add_bulk(&cmd, pages[i].key,
						   strlen(pages[i].key));
	}
	if (ret)
		goto out_free;

	ret = rswap_sock_send(conn->sock, request, cmd.len);
	for (i = 0; !ret && i < nr; i++) {
		data = kmap_local_page(pages[i].page);
		ret = rswap_redis_read_bulk(conn->sock, data, len);
		kunmap_local(data);
	}

out_free:
	kvfree(request);
	if (rswap_redis_transport_error(ret))
		rswap_redis_drop(conn);
	return ret;
}

static int rswap_redis_store(struct rswap_kv_page *pages, unsigned int nr,
			     size_t len)
{
	struct rswap_redis_conn *conn;
	unsigned int tries = 0;
	int ret;

	if (!nr)
		return -EINVAL;

	conn = rswap_redis_conn_get();
	if (!conn)
		return -ENOMEM;
retry:
	ret = rswap_redis_ensure(conn);
	if (!ret)
		ret = rswap_redis_do_store(conn, pages, nr, len);
	if (ret && rswap_redis_transport_error(ret) && !conn->sock &&
	    tries++ < 1) {
		atomic64_inc(&rswap_redis_retries);
		goto retry;
	}
	rswap_redis_conn_put(conn);
	return ret;
}

static int rswap_redis_load(struct rswap_kv_page *pages, unsigned int nr,
			    size_t len)
{
	struct rswap_redis_conn *conn;
	unsigned int tries = 0;
	int ret;

	if (!nr)
		return -EINVAL;

	conn = rswap_redis_conn_get();
	if (!conn)
		return -ENOMEM;
retry:
	ret = rswap_redis_ensure(conn);
	if (!ret)
		ret = rswap_redis_do_load(conn, pages, nr, len);
	if (ret && rswap_redis_transport_error(ret) && !conn->sock &&
	    tries++ < 1) {
		atomic64_inc(&rswap_redis_retries);
		goto retry;
	}
	rswap_redis_conn_put(conn);
	return ret;
}

/* ---------- Backend registration ---------- */

static void rswap_redis_show_stats(struct seq_file *m)
{
	seq_printf(m, "redis_connects\t%llu\n",
		   atomic64_read(&rswap_redis_connects));
	seq_printf(m, "redis_reuses\t%llu\n",
		   atomic64_read(&rswap_redis_reuses));
	seq_printf(m, "redis_dropped\t%llu\n",
		   atomic64_read(&rswap_redis_dropped));
	seq_printf(m, "redis_retries\t%llu\n",
		   atomic64_read(&rswap_redis_retries));
}

static int rswap_redis_init(const struct rswap_kv_config *cfg)
{
	if (strscpy(rswap_redis.host, cfg->host, sizeof(rswap_redis.host)) < 0)
		return -EINVAL;
	if (strscpy(rswap_redis.user, cfg->user ?: "",
		    sizeof(rswap_redis.user)) < 0)
		return -EINVAL;
	if (strscpy(rswap_redis.password, cfg->password ?: "",
		    sizeof(rswap_redis.password)) < 0)
		return -EINVAL;

	rswap_redis.port = cfg->port;
	rswap_redis.db = cfg->db;
	rswap_redis.send_timeout_ms = cfg->send_timeout_ms;
	rswap_redis.recv_timeout_ms = cfg->recv_timeout_ms;
	return 0;
}

const struct rswap_backend rswap_redis_backend = {
	.name			= "redis",
	.description		= "Redis RESP key-value store",
	.default_host		= RSWAP_REDIS_DEFAULT_HOST,
	.default_port		= RSWAP_REDIS_DEFAULT_PORT,
	.default_send_timeout_ms = RSWAP_REDIS_SEND_TIMEOUT_MS,
	.default_recv_timeout_ms = RSWAP_REDIS_RECV_TIMEOUT_MS,
	.init			= rswap_redis_init,
	.store			= rswap_redis_store,
	.load			= rswap_redis_load,
	.show_stats		= rswap_redis_show_stats,
};
