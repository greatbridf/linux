/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mm/rswap_backend.h - pluggable key-value backends for rswap
 *
 * rswap itself only decides *what* to store and under which key; *how* the
 * page reaches the remote store is delegated to a KV backend.  A backend
 * stores one base page image under the userspace supplied SHA-256 digest of
 * that page.
 *
 * The key is always the 64 character lowercase hex form of a digest that was
 * attached by user space and persisted in the per-device table.  Backends must
 * never invent or derive a key of their own.
 */

#ifndef _MM_RSWAP_BACKEND_H
#define _MM_RSWAP_BACKEND_H

#include <linux/types.h>

struct socket;

/* Longest KV key rswap ever produces: SHA-256 as hex plus the NUL. */
#define RSWAP_KV_KEY_LEN	65
/* Room for a host name, an IPv4 literal or a future address family. */
#define RSWAP_KV_HOST_LEN	64

/*
 * Resolved backend configuration.  Everything a backend needs is filled in
 * with an effective value before ->init() is called; backends only copy it.
 */
struct rswap_kv_config {
	const char	*host;		/* endpoint address */
	u16		port;		/* endpoint port */
	const char	*user;		/* RESP ACL user, NULL if unused */
	const char	*password;	/* RESP AUTH secret, NULL if unused */
	unsigned int	db;		/* Redis database number */
	unsigned int	send_timeout_ms;
	unsigned int	recv_timeout_ms;
};

/*
 * A KV backend.
 *
 * @name:			selector used by the rswap.backend parameter
 * @description:		human readable name, for logs
 * @default_host:		used when rswap.host is not set
 * @default_port:		used when rswap.port is not set
 * @default_send_timeout_ms:	used when rswap.send_timeout_ms is not set
 * @default_recv_timeout_ms:	used when rswap.recv_timeout_ms is not set
 * @init:			optional; copy @cfg, validate it, return -errno
 * @store:			write @len bytes at @key
 * @load:			read @len bytes from @key
 *
 * ->store() and ->load() run in swap I/O context under GFP_NOIO and must not
 * touch the filesystem.  They may sleep.  @load() returns -ENOENT when the
 * key is absent; a short or oversized object is an error, never a partial
 * page.
 */
struct rswap_backend {
	const char	*name;
	const char	*description;
	const char	*default_host;
	u16		default_port;
	unsigned int	default_send_timeout_ms;
	unsigned int	default_recv_timeout_ms;

	int		(*init)(const struct rswap_kv_config *cfg);
	int		(*store)(const char *key, const void *data, size_t len);
	int		(*load)(const char *key, void *data, size_t len);
};

/*
 * TCP transport shared by the backends (mm/rswap_sock.c).  A backend opens
 * one connection per page operation and closes it again, so these helpers
 * keep no state and need no locking.
 */
struct socket *rswap_sock_connect(const char *host, u16 port,
				  unsigned int send_timeout_ms,
				  unsigned int recv_timeout_ms);
void rswap_sock_close(struct socket *sock);
int rswap_sock_send(struct socket *sock, const void *data, size_t len);
int rswap_sock_recv(struct socket *sock, void *buf, size_t len);

#ifdef CONFIG_RSWAP_KV_HTTP
extern const struct rswap_backend rswap_http_backend;
#endif
#ifdef CONFIG_RSWAP_KV_REDIS
extern const struct rswap_backend rswap_redis_backend;
#endif

#endif /* _MM_RSWAP_BACKEND_H */
