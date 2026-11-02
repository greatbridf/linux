// SPDX-License-Identifier: GPL-2.0
/*
 * mm/rswap_redis.c - rswap KV backend speaking RESP to a Redis server
 *
 * Keys are the same 64 character lowercase SHA-256 hex strings the other
 * backends use, so a Redis dump can be audited directly against the digests
 * user space attached.  Values are raw base page images.
 *
 * One page operation is one connection with the commands pipelined:
 *
 *   write:  AUTH* SELECT* SET <key> <page bytes>
 *   read:   AUTH* SELECT* GET <key>
 *
 * (*) only when a password resp. a non-zero database is configured.
 *
 * Nothing is cached across operations.  Swap I/O runs on many CPUs at once,
 * so a shared connection would need a sleeping lock in the I/O path; opening
 * a connection per page keeps the backend stateless instead.
 */

#define pr_fmt(fmt) "rswap: " fmt

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/kstrtox.h>
#include <linux/net.h>

#include "rswap_backend.h"

#define RSWAP_REDIS_DEFAULT_HOST	"127.0.0.1"
#define RSWAP_REDIS_DEFAULT_PORT	6379
#define RSWAP_REDIS_SEND_TIMEOUT_MS	10000
#define RSWAP_REDIS_RECV_TIMEOUT_MS	10000
/* AUTH + SELECT + the SET/GET header, including bulk length prefixes. */
#define RSWAP_REDIS_MAX_CMD		320
/* Status, error and bulk length lines are all tiny. */
#define RSWAP_REDIS_MAX_LINE		256

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

struct rswap_redis_cmd {
	char	buf[RSWAP_REDIS_MAX_CMD];
	size_t	len;
};

/* Append a "*<argc>\r\n" array header. */
static int rswap_redis_add_array(struct rswap_redis_cmd *cmd, unsigned int argc)
{
	char prefix[16];
	int len;

	len = snprintf(prefix, sizeof(prefix), "*%u\r\n", argc);
	if (len < 0 || cmd->len + len > sizeof(cmd->buf))
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
	if (plen < 0 || cmd->len + plen + 2 > sizeof(cmd->buf))
		return -ENOSPC;
	memcpy(cmd->buf + cmd->len, prefix, plen);
	cmd->len += plen;
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
	if (cmd->len + len + 2 > sizeof(cmd->buf))
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

/* ---------- Backend operations ---------- */

static struct socket *rswap_redis_open(void)
{
	return rswap_sock_connect(rswap_redis.host, rswap_redis.port,
				  rswap_redis.send_timeout_ms,
				  rswap_redis.recv_timeout_ms);
}

static int rswap_redis_store(const char *key, const void *data, size_t len)
{
	struct rswap_redis_cmd cmd = { };
	struct socket *sock;
	unsigned int replies;
	unsigned int i;
	int ret;

	sock = rswap_redis_open();
	if (IS_ERR(sock))
		return PTR_ERR(sock);

	ret = rswap_redis_queue_preamble(&cmd, &replies);
	if (!ret)
		ret = rswap_redis_add_array(&cmd, 3);
	if (!ret)
		ret = rswap_redis_add_bulk(&cmd, "SET", 3);
	if (!ret)
		ret = rswap_redis_add_bulk(&cmd, key, strlen(key));
	/* The page is sent from its own buffer, not copied into @cmd. */
	if (!ret)
		ret = rswap_redis_add_bulk_header(&cmd, len);
	if (ret)
		goto out;

	ret = rswap_sock_send(sock, cmd.buf, cmd.len);
	if (!ret && len)
		ret = rswap_sock_send(sock, data, len);
	if (!ret)
		ret = rswap_sock_send(sock, "\r\n", 2);
	if (ret)
		goto out;

	for (i = 0; i <= replies; i++) {
		ret = rswap_redis_status(sock, "OK");
		if (ret)
			goto out;
	}
out:
	rswap_sock_close(sock);
	return ret;
}

static int rswap_redis_load(const char *key, void *data, size_t len)
{
	struct rswap_redis_cmd cmd = { };
	struct socket *sock;
	unsigned int replies;
	unsigned int i;
	int ret;

	sock = rswap_redis_open();
	if (IS_ERR(sock))
		return PTR_ERR(sock);

	ret = rswap_redis_queue_preamble(&cmd, &replies);
	if (!ret)
		ret = rswap_redis_add_array(&cmd, 2);
	if (!ret)
		ret = rswap_redis_add_bulk(&cmd, "GET", 3);
	if (!ret)
		ret = rswap_redis_add_bulk(&cmd, key, strlen(key));
	if (!ret)
		ret = rswap_sock_send(sock, cmd.buf, cmd.len);
	if (ret)
		goto out;

	for (i = 0; i < replies; i++) {
		ret = rswap_redis_status(sock, "OK");
		if (ret)
			goto out;
	}
	ret = rswap_redis_read_bulk(sock, data, len);
out:
	rswap_sock_close(sock);
	return ret;
}

/* ---------- Backend registration ---------- */

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
};
