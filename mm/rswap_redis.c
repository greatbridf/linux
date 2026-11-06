// SPDX-License-Identifier: GPL-2.0
/*
 * mm/rswap_redis.c - rswap KV backend speaking RESP to a Redis server
 *
 * Keys are the same hex digest strings the other backends use, so a Redis dump
 * can be audited directly against the digests the programs supplied: 96
 * characters, RSWAP_KV_KEY_LEN bytes with the NUL.  Values are raw base page
 * images.
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
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mempool.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/semaphore.h>
#include <linux/string.h>
#include <linux/kstrtox.h>
#include <linux/net.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>

#include "rswap_backend.h"

#define RSWAP_REDIS_DEFAULT_HOST	"127.0.0.1"
#define RSWAP_REDIS_DEFAULT_PORT	6379
#define RSWAP_REDIS_CONNECT_TIMEOUT_MS	10000
#define RSWAP_REDIS_SEND_TIMEOUT_MS	10000
#define RSWAP_REDIS_RECV_TIMEOUT_MS	10000
/* Status, error and bulk length lines are all tiny. */
#define RSWAP_REDIS_MAX_LINE		256
/* Room for one "$<key length>\r\n" including its NUL. */
#define RSWAP_REDIS_KEY_BULK_LEN	16
/* Cached connections; more concurrent batches than this fall back to new. */
#define RSWAP_REDIS_POOL_MAX		8
/* Flush a full vector array without waiting for the pipelined replies. */
#define RSWAP_CMD_BVECS			(3 * RSWAP_BATCH_MAX)

static struct {
	char		host[RSWAP_KV_HOST_LEN];
	u16		port;
	char		user[RSWAP_KV_HOST_LEN];
	char		password[128];
	unsigned int	db;
	unsigned int	send_timeout_ms;
	unsigned int	recv_timeout_ms;
} rswap_redis;

/*
 * Budget for one batch: one connect, one send and two receive timeouts.  A
 * batch is one pipelined round trip, so the reply stream with its lines and
 * bulk trailers fits in that.  The socket timeouts still bound how long the
 * peer may stay silent between two operations.
 */
static unsigned long rswap_redis_deadline(void)
{
	return rswap_sock_deadline(RSWAP_REDIS_CONNECT_TIMEOUT_MS +
				   rswap_redis.send_timeout_ms +
				   2 * rswap_redis.recv_timeout_ms);
}

/* ---------- RESP wire format ---------- */

enum {
	RSWAP_CMD_AUTH,
	RSWAP_CMD_GET,
	RSWAP_CMD_SET,
	RSWAP_CMD_SELECT,

	RSWAP_CMD_ARG_2,
	RSWAP_CMD_ARG_3,

	RSWAP_CMD_BULK_PAGE_SIZE,
	RSWAP_CMD_CRLF,
	RSWAP_CMD_USER,
	RSWAP_CMD_PASSWORD,
	RSWAP_CMD_DB,

	NR_RSWAP_CMD_PARTS,
};

static struct bio_vec rswap_common_part_bios[NR_RSWAP_CMD_PARTS];
static struct mempool *rswap_redis_cmd_pool;

/* All vectors reference the original fragments, keys and page payloads. */
struct rswap_redis_cmd {
	struct socket	*sock;
	unsigned long	deadline;
	size_t		len;
	unsigned int	nr;
	unsigned int	nr_bulk;	/* used slots in @bulk */

	/* "$<key length>\r\n", one slot per key of the batch being built. */
	char		bulk[RSWAP_BATCH_MAX][RSWAP_REDIS_KEY_BULK_LEN];
	struct bio_vec	bvecs[RSWAP_CMD_BVECS];
};

static int rswap_redis_send_cmd(struct rswap_redis_cmd *cmd);

static struct rswap_redis_cmd *rswap_redis_cmd_alloc(struct socket *sock,
						     unsigned long deadline)
{
	struct rswap_redis_cmd *cmd;

	cmd = mempool_alloc(rswap_redis_cmd_pool, GFP_NOIO);
	if (cmd) {
		cmd->sock = sock;
		cmd->deadline = deadline;
		cmd->len = 0;
		cmd->nr = 0;
		cmd->nr_bulk = 0;
	}
	return cmd;
}

static int rswap_redis_add_bvec(struct rswap_redis_cmd *cmd,
				const struct bio_vec *bv)
{
	int ret;

	if (cmd->nr == ARRAY_SIZE(cmd->bvecs)) {
		ret = rswap_redis_send_cmd(cmd);
		if (ret)
			return ret;
	}
	cmd->bvecs[cmd->nr++] = *bv;
	cmd->len += bv->bv_len;
	return 0;
}

static int rswap_redis_add_part(struct rswap_redis_cmd *cmd, unsigned int part)
{
	return rswap_redis_add_bvec(cmd, &rswap_common_part_bios[part]);
}

/* Append a "*<argc>\r\n" array header. */
static int rswap_redis_add_array(struct rswap_redis_cmd *cmd, unsigned int argc)
{
	if (argc != 2 && argc != 3)
		return -EINVAL;
	return rswap_redis_add_part(cmd, argc == 2 ? RSWAP_CMD_ARG_2 :
				    RSWAP_CMD_ARG_3);
}

/* Append @len bytes of kernel memory at @data. */
static int rswap_redis_add_buf(struct rswap_redis_cmd *cmd, const void *data,
			       size_t len)
{
	struct bio_vec bv;
	struct page *page;
	size_t chunk;
	int ret;

	/* The buffer can live in vmalloc memory and can cross a page. */
	while (len) {
		chunk = min_t(size_t, len, PAGE_SIZE - offset_in_page(data));
		page = is_vmalloc_addr(data) ? vmalloc_to_page(data) :
			virt_to_page(data);
		bvec_set_page(&bv, page, chunk, offset_in_page(data));
		ret = rswap_redis_add_bvec(cmd, &bv);
		if (ret)
			return ret;
		data += chunk;
		len -= chunk;
	}
	return 0;
}

/*
 * Append the bulk length header of @key and then the key itself.
 *
 * Both are taken from @key, so the bytes on the wire are exactly the key
 * string; ->store() and ->load() have already rejected a key that is not a
 * full digest, so every key of a batch has the same width.
 */
static int rswap_redis_add_key(struct rswap_redis_cmd *cmd, const char *key)
{
	size_t len = strlen(key);
	char *bulk;
	int bulk_len;
	int ret;

	if (cmd->nr_bulk == ARRAY_SIZE(cmd->bulk))
		return -EINVAL;

	bulk = cmd->bulk[cmd->nr_bulk++];
	bulk_len = scnprintf(bulk, sizeof(cmd->bulk[0]), "$%zu\r\n", len);
	ret = rswap_redis_add_buf(cmd, bulk, bulk_len);
	if (ret)
		return ret;
	return rswap_redis_add_buf(cmd, key, len);
}

/* Append the prefilled wire fragments and the original key pages. */
static int rswap_redis_add_header(struct rswap_redis_cmd *cmd, const char *key,
				  bool store)
{
	unsigned int array = store ? RSWAP_CMD_ARG_3 : RSWAP_CMD_ARG_2;
	unsigned int verb = store ? RSWAP_CMD_SET : RSWAP_CMD_GET;
	int ret;

	ret = rswap_redis_add_part(cmd, array);
	if (!ret)
		ret = rswap_redis_add_part(cmd, verb);
	if (!ret)
		ret = rswap_redis_add_key(cmd, key);
	if (!ret)
		ret = rswap_redis_add_part(cmd, RSWAP_CMD_CRLF);
	if (!ret && store)
		ret = rswap_redis_add_part(cmd, RSWAP_CMD_BULK_PAGE_SIZE);
	return ret;
}

static int rswap_redis_send_cmd(struct rswap_redis_cmd *cmd)
{
	int ret;

	ret = rswap_sock_send_bvecs(cmd->sock, cmd->bvecs, cmd->nr, cmd->len,
				    cmd->deadline);
	if (ret)
		return ret;
	cmd->nr = 0;
	cmd->len = 0;
	cmd->nr_bulk = 0;
	return 0;
}

/*
 * Buffered reply reader.  The socket is read in chunks instead of one byte per
 * call, so a reply costs one receive; bytes that arrive beyond the reply being
 * parsed stay in @buf for the next one.  The batch is one pipelined exchange,
 * so @deadline bounds the whole of it.
 */
struct rswap_redis_reader {
	struct socket	*sock;
	unsigned long	deadline;
	size_t		filled;	/* bytes read into @buf */
	size_t		used;	/* consumed prefix of @buf */
	char		buf[RSWAP_REDIS_MAX_LINE];
};

static void rswap_redis_reader_init(struct rswap_redis_reader *reader,
				    struct socket *sock, unsigned long deadline)
{
	reader->sock = sock;
	reader->deadline = deadline;
	reader->filled = 0;
	reader->used = 0;
}

/* Are there reply bytes in the buffer that no parser has consumed yet? */
static bool rswap_redis_reader_pending(const struct rswap_redis_reader *reader)
{
	return reader->used != reader->filled;
}

/* Make at least one unread byte available in @reader. */
static int rswap_redis_reader_fill(struct rswap_redis_reader *reader)
{
	int ret;

	if (rswap_redis_reader_pending(reader))
		return 0;
	if (rswap_sock_expired(reader->deadline))
		return -ETIMEDOUT;
	ret = rswap_sock_recv(reader->sock, reader->buf, sizeof(reader->buf),
			      reader->deadline);
	if (ret <= 0)
		return ret ? ret : -ECONNRESET;
	reader->filled = ret;
	reader->used = 0;
	return 0;
}

/* Copy @len buffered bytes into @buf, reading from the socket when needed. */
static int rswap_redis_reader_read(struct rswap_redis_reader *reader, char *buf,
				   size_t len)
{
	size_t i;
	int ret;

	for (i = 0; i < len; i++) {
		ret = rswap_redis_reader_fill(reader);
		if (ret)
			return ret;
		buf[i] = reader->buf[reader->used++];
	}
	return 0;
}

/* Read one CRLF terminated line, without the terminator. */
static int rswap_redis_read_line(struct rswap_redis_reader *reader, char *line,
				 size_t size)
{
	size_t len = 0;
	int ret;

	for (;;) {
		if (len + 2 > size)
			return -ENOSPC;
		ret = rswap_redis_reader_fill(reader);
		if (ret)
			return ret;
		line[len] = reader->buf[reader->used++];
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
static int rswap_redis_status(struct rswap_redis_reader *reader,
			      const char *expected)
{
	char line[RSWAP_REDIS_MAX_LINE];
	int ret;

	ret = rswap_redis_read_line(reader, line, sizeof(line));
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

/* Read a bulk reply into @page, which must be exactly @len bytes long. */
static int rswap_redis_read_bulk(struct rswap_redis_reader *reader,
				 struct page *page, size_t len)
{
	char line[RSWAP_REDIS_MAX_LINE];
	char trailer[2];
	size_t off = 0;
	long value_len;
	int ret;

	ret = rswap_redis_read_line(reader, line, sizeof(line));
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

	/* Payload bytes that arrived with the length line come first. */
	if (rswap_redis_reader_pending(reader)) {
		void *addr;

		off = min_t(size_t, reader->filled - reader->used, len);
		addr = kmap_local_page(page);
		memcpy(addr, reader->buf + reader->used, off);
		kunmap_local(addr);
		reader->used += off;
	}

	ret = rswap_sock_recv_page(reader->sock, page, off, len - off,
				   reader->deadline);
	if (ret)
		return ret;

	/* Trailing CRLF of the bulk string. */
	ret = rswap_redis_reader_read(reader, trailer, sizeof(trailer));
	if (ret)
		return ret;
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
			ret = rswap_redis_add_part(cmd, RSWAP_CMD_AUTH);
		if (!ret && rswap_redis.user[0])
			ret = rswap_redis_add_part(cmd, RSWAP_CMD_USER);
		if (!ret)
			ret = rswap_redis_add_part(cmd, RSWAP_CMD_PASSWORD);
		if (ret)
			return ret;
		(*replies)++;
	}

	if (rswap_redis.db) {
		ret = rswap_redis_add_array(cmd, 2);
		if (!ret)
			ret = rswap_redis_add_part(cmd, RSWAP_CMD_SELECT);
		if (!ret)
			ret = rswap_redis_add_part(cmd, RSWAP_CMD_DB);
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

/*
 * Errors that mean the connection itself failed.  Only those are retried,
 * because only then can a fresh connection behave differently: the batch is
 * idempotent.  An answer from a live server (a missing key, an object of the
 * wrong length, a RESP error such as a wrong password) or a local allocation
 * or argument failure must not burn the single retry.
 */
static bool rswap_redis_transport_error(int err)
{
	switch (err) {
	case 0:
	case -ENOENT:
	case -EMSGSIZE:
	case -EACCES:
	case -ENOMEM:
	case -EINVAL:
		return false;
	default:
		return true;
	}
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
static int rswap_redis_ensure(struct rswap_redis_conn *conn,
			      unsigned long deadline)
{
	struct rswap_redis_reader reader;
	struct rswap_redis_cmd *cmd;
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

	/* A retry that already spent the budget must not start a fresh one. */
	if (rswap_sock_expired(deadline))
		return -ETIMEDOUT;

	conn->sock = rswap_sock_connect(rswap_redis.host, rswap_redis.port,
					RSWAP_REDIS_CONNECT_TIMEOUT_MS,
					rswap_redis.send_timeout_ms,
					rswap_redis.recv_timeout_ms);
	if (IS_ERR(conn->sock)) {
		ret = PTR_ERR(conn->sock);
		conn->sock = NULL;
		return ret;
	}
	atomic64_inc(&rswap_redis_connects);

	cmd = rswap_redis_cmd_alloc(conn->sock, deadline);
	if (!cmd) {
		rswap_redis_drop(conn);
		return -ENOMEM;
	}
	rswap_redis_reader_init(&reader, conn->sock, deadline);
	ret = rswap_redis_queue_preamble(cmd, &replies);
	if (!ret && replies) {
		ret = rswap_redis_send_cmd(cmd);
		for (i = 0; !ret && i < replies; i++)
			ret = rswap_redis_status(&reader, "OK");
		if (!ret && rswap_redis_reader_pending(&reader))
			ret = -EPROTO;
	}
	mempool_free(cmd, rswap_redis_cmd_pool);
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
				size_t len, unsigned long deadline)
{
	struct rswap_redis_reader reader;
	struct rswap_redis_cmd *cmd;
	struct bio_vec bv;
	unsigned int i;
	int ret = 0;

	cmd = rswap_redis_cmd_alloc(conn->sock, deadline);
	if (!cmd)
		return -ENOMEM;

	for (i = 0; !ret && i < nr; i++) {
		ret = rswap_redis_add_header(cmd, pages[i].key, true);
		/* A bulk payload must follow its own header directly. */
		if (!ret) {
			bvec_set_page(&bv, pages[i].page, len, 0);
			ret = rswap_redis_add_bvec(cmd, &bv);
		}
		if (!ret)
			ret = rswap_redis_add_part(cmd, RSWAP_CMD_CRLF);
	}
	if (!ret)
		ret = rswap_redis_send_cmd(cmd);

	rswap_redis_reader_init(&reader, conn->sock, deadline);
	for (i = 0; !ret && i < nr; i++)
		ret = rswap_redis_status(&reader, "OK");
	if (!ret && rswap_redis_reader_pending(&reader))
		ret = -EPROTO;

	mempool_free(cmd, rswap_redis_cmd_pool);
	/* Unread replies must never reach the next pooled request. */
	if (ret)
		rswap_redis_drop(conn);
	return ret;
}

static int rswap_redis_do_load(struct rswap_redis_conn *conn,
			       struct rswap_kv_page *pages, unsigned int nr,
			       size_t len, unsigned long deadline)
{
	struct rswap_redis_reader reader;
	struct rswap_redis_cmd *cmd;
	unsigned int i;
	int ret = 0;

	cmd = rswap_redis_cmd_alloc(conn->sock, deadline);
	if (!cmd)
		return -ENOMEM;

	rswap_redis_reader_init(&reader, conn->sock, deadline);
	for (i = 0; !ret && i < nr; i++)
		ret = rswap_redis_add_header(cmd, pages[i].key, false);
	if (!ret)
		ret = rswap_redis_send_cmd(cmd);
	if (ret)
		goto out_free;

	for (i = 0; i < nr; i++) {
		ret = rswap_redis_read_bulk(&reader, pages[i].page, len);
		if (ret)
			break;
	}
	if (!ret && rswap_redis_reader_pending(&reader))
		ret = -EPROTO;

out_free:
	mempool_free(cmd, rswap_redis_cmd_pool);
	/*
	 * Unread replies or payload must never reach the next pooled request, so
	 * the connection is dropped whenever the batch stopped before the end of
	 * the reply stream.  A missing key is a complete reply, so a routine
	 * swapin miss for the last page of a batch keeps the connection.
	 */
	if (ret && !(ret == -ENOENT && i + 1 == nr &&
		     !rswap_redis_reader_pending(&reader)))
		rswap_redis_drop(conn);
	return ret;
}

/* Reject a batch whose keys are not the full digest strings the core made. */
static int rswap_redis_validate(struct rswap_kv_page *pages, unsigned int nr,
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

static int rswap_redis_store(struct rswap_kv_page *pages, unsigned int nr,
			     size_t len)
{
	struct rswap_redis_conn *conn;
	unsigned long deadline;
	unsigned int tries = 0;
	int ret;

	ret = rswap_redis_validate(pages, nr, len);
	if (ret)
		return ret;

	conn = rswap_redis_conn_get();
	if (!conn)
		return -ENOMEM;
	/* The deadline covers both attempts of the retry-once policy. */
	deadline = rswap_redis_deadline();
retry:
	ret = rswap_redis_ensure(conn, deadline);
	if (!ret)
		ret = rswap_redis_do_store(conn, pages, nr, len, deadline);
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
	unsigned long deadline;
	unsigned int tries = 0;
	int ret;

	ret = rswap_redis_validate(pages, nr, len);
	if (ret)
		return ret;

	conn = rswap_redis_conn_get();
	if (!conn)
		return -ENOMEM;
	/* The deadline covers both attempts of the retry-once policy. */
	deadline = rswap_redis_deadline();
retry:
	ret = rswap_redis_ensure(conn, deadline);
	if (!ret)
		ret = rswap_redis_do_load(conn, pages, nr, len, deadline);
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

static int __init rswap_redis_init_parts(void)
{
	static const char * const parts[NR_RSWAP_CMD_PARTS] = {
		[RSWAP_CMD_AUTH] = "$4\r\nAUTH\r\n",
		[RSWAP_CMD_GET] = "$3\r\nGET\r\n",
		[RSWAP_CMD_SET] = "$3\r\nSET\r\n",
		[RSWAP_CMD_SELECT] = "$6\r\nSELECT\r\n",
		[RSWAP_CMD_ARG_2] = "*2\r\n",
		[RSWAP_CMD_ARG_3] = "*3\r\n",
		[RSWAP_CMD_CRLF] = "\r\n",
	};
	struct folio *folio;
	char db[16];
	char *buf;
	size_t offset = 0;
	unsigned int i;
	int len;
	int ret = -ENOSPC;

	folio = folio_alloc(GFP_KERNEL | __GFP_ZERO, 0);
	if (!folio)
		return -ENOMEM;
	buf = folio_address(folio);
	snprintf(db, sizeof(db), "%u", rswap_redis.db);
	for (i = 0; i < NR_RSWAP_CMD_PARTS; i++) {
		const char *arg;
		size_t remaining = PAGE_SIZE - offset;

		if (parts[i]) {
			len = snprintf(buf + offset, remaining, "%s", parts[i]);
		} else if (i == RSWAP_CMD_BULK_PAGE_SIZE) {
			len = snprintf(buf + offset, remaining, "$%zu\r\n",
				       (size_t)PAGE_SIZE);
		} else {
			switch (i) {
			case RSWAP_CMD_USER:
				arg = rswap_redis.user;
				break;
			case RSWAP_CMD_PASSWORD:
				arg = rswap_redis.password;
				break;
			case RSWAP_CMD_DB:
				arg = db;
				break;
			default:
				ret = -EINVAL;
				goto out_free;
			}
			len = snprintf(buf + offset, remaining, "$%zu\r\n%s\r\n",
				       strlen(arg), arg);
		}
		if (len < 0 || len >= remaining)
			goto out_free;
		bvec_set_folio(&rswap_common_part_bios[i], folio, len, offset);
		offset += len;
	}

	/* Each connection holds at most one command, including its preamble. */
	rswap_redis_cmd_pool = mempool_create_kmalloc_pool(RSWAP_REDIS_POOL_MAX,
							 sizeof(struct rswap_redis_cmd));
	if (!rswap_redis_cmd_pool) {
		ret = -ENOMEM;
		goto out_free;
	}
	/* The common folio and command pool live as long as this boot backend. */
	return 0;

out_free:
	memzero_explicit(buf, PAGE_SIZE);
	memset(rswap_common_part_bios, 0, sizeof(rswap_common_part_bios));
	folio_put(folio);
	return ret;
}

static int __init rswap_redis_init(const struct rswap_kv_config *cfg)
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
	return rswap_redis_init_parts();
}

/* Only ->init points into init text; the core calls it during boot setup. */
const struct rswap_backend rswap_redis_backend __refconst = {
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
