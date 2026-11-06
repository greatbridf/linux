/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mm/rswap_backend.h - pluggable key-value backends for rswap
 *
 * rswap itself only decides *what* to store and under which key; *how* the
 * page reaches the remote store is delegated to a KV backend.  A backend
 * stores one base page image under the digest that a userspace or BPF program
 * supplied for that page.
 *
 * The key is the hex form of that digest, as the core rendered it with
 * bin2hex(): RSWAP_HASH_HEXLEN (2 * RSWAP_HASH_LEN = 96) characters, which is
 * RSWAP_KV_KEY_LEN bytes including the terminating NUL.  The digest itself is
 * program supplied and opaque here; today's digest programs emit 32 bytes of
 * SHA-256, and the legacy /proc/sys/vm/rswap/attach path zero-extends such a
 * digest to the 48 byte slot width, but nothing in the key layout depends on
 * that.  Backends must never invent or derive a key of their own.
 */

#ifndef _MM_RSWAP_BACKEND_H
#define _MM_RSWAP_BACKEND_H

#include <linux/types.h>

struct bio_vec;
struct page;
struct seq_file;
struct socket;

/* One KV key: the digest as hex plus the NUL, 2 * RSWAP_HASH_LEN + 1 bytes. */
#define RSWAP_KV_KEY_LEN	97	/* 2 * RSWAP_HASH_LEN + NUL */
/* Room for a host name, an IPv4 literal or a future address family. */
#define RSWAP_KV_HOST_LEN	64
/*
 * Most pages the core hands to one ->store()/->load() call.  A swap request
 * carries up to SWAP_CLUSTER_MAX pages; batching them lets a backend pay one
 * round trip for several pages.  One page costs only a fraction of a round
 * trip, so a full 32 page batch is one request; the pages travel between the
 * folio pages and the store directly, so the batch carries only the keys and
 * one struct rswap_kv_page per page.
 */
#define RSWAP_BATCH_MAX		32

/* One base page image together with the KV key it belongs to. */
struct rswap_kv_page {
	const char	*key;		/* hex digest, RSWAP_KV_KEY_LEN bytes */
	struct page	*page;		/* exactly one base page image */
};

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
};

/*
 * A KV backend.
 *
 * @name:			selector used by the rswap.backend parameter
 * @description:		human readable name, for logs
 * @default_host:		used when rswap.host is not set
 * @default_port:		used when rswap.port is not set
 * @default_send_timeout_ms:	used while rswap.send_timeout_ms is 0
 * @default_recv_timeout_ms:	used while rswap.recv_timeout_ms is 0
 * @init:			optional; copy @cfg, validate it, return -errno
 * @store:			write @nr page images
 * @load:			read @nr page images
 * @show_stats:			optional, append backend counters to debugfs
 *
 * ->store() and ->load() move @nr page images of @len bytes each from and to
 * @pages[].  @nr is between 1 and RSWAP_BATCH_MAX; keys stay valid only for
 * the duration of the call.  A backend spends as few round trips as its
 * protocol allows: Redis pipelines all @nr keys over one pooled connection,
 * so a batch is one round trip, while HTTP/1.0 carries one object per request
 * and so needs one per page.  Moving the pages one at a time is still correct.
 *
 * They run in swap I/O context under GFP_NOIO and must not touch the
 * filesystem.  They may sleep.  ->load() returns -ENOENT when a key is
 * absent; a short or oversized object is an error, never a partial page.  On
 * error the caller drops the whole swap request.
 */
struct rswap_backend {
	const char	*name;
	const char	*description;
	const char	*default_host;
	u16		default_port;
	unsigned int	default_send_timeout_ms;
	unsigned int	default_recv_timeout_ms;

	int		(*init)(const struct rswap_kv_config *cfg);
	int		(*store)(struct rswap_kv_page *pages, unsigned int nr,
				size_t len);
	int		(*load)(struct rswap_kv_page *pages, unsigned int nr,
			       size_t len);
	void		(*show_stats)(struct seq_file *m);
};

/*
 * Effective backend timeouts in milliseconds, for a request that starts now:
 * the rswap.send_timeout_ms / rswap.recv_timeout_ms parameter, or the
 * selected backend's default while it is 0.  A backend asks for them when it
 * budgets a request and when it opens a connection, so a runtime write through
 * /sys/module/rswap/parameters/ reaches the next request, while a batch that
 * already started keeps the budget it computed and a pooled connection keeps
 * the socket timeouts it was opened with.
 */
unsigned int rswap_kv_send_timeout(void);
unsigned int rswap_kv_recv_timeout(void);

/*
 * TCP transport shared by the backends (mm/rswap_sock.c).  The helpers keep
 * no state and need no locking of their own; whoever owns @sock decides how
 * long it lives.  HTTP/1.0 opens one connection per object, Redis keeps a pool
 * and reuses a connection for many batches.
 *
 * The socket timeouts only bound one operation each, so the helpers that may
 * loop take the absolute deadline of the request they serve, as returned by
 * rswap_sock_deadline(), and fail with -ETIMEDOUT once it has passed.  That is
 * what keeps the wall time of one request bounded however slowly the peer
 * answers.
 *
 * An operation interrupted by a signal (-EINTR, -ERESTARTSYS) transferred
 * nothing, so the helpers repeat it while the request deadline allows instead
 * of reporting it.  No other errno is retried here: whether a transport
 * failure may be retried depends on the protocol and is decided by the
 * backend that knows which of its operations are idempotent.
 */
struct socket *rswap_sock_connect(const char *host, u16 port,
				  unsigned int connect_timeout_ms,
				  unsigned int send_timeout_ms,
				  unsigned int recv_timeout_ms);
void rswap_sock_close(struct socket *sock);
bool rswap_sock_alive(struct socket *sock);
unsigned long rswap_sock_deadline(unsigned int timeout_ms);
bool rswap_sock_expired(unsigned long deadline);
int rswap_sock_send(struct socket *sock, const void *data, size_t len,
		    unsigned long deadline);
int rswap_sock_recv(struct socket *sock, void *buf, size_t len,
		    unsigned long deadline);
int rswap_sock_send_bvecs(struct socket *sock, struct bio_vec *bvecs,
			  unsigned int nr, size_t len, unsigned long deadline);
int rswap_sock_send_page(struct socket *sock, struct page *page, size_t len,
			 unsigned long deadline);
int rswap_sock_recv_page(struct socket *sock, struct page *page, size_t off,
			 size_t len, unsigned long deadline);

#ifdef CONFIG_RSWAP_KV_HTTP
extern const struct rswap_backend rswap_http_backend;
#endif
#ifdef CONFIG_RSWAP_KV_REDIS
extern const struct rswap_backend rswap_redis_backend;
#endif

#endif /* _MM_RSWAP_BACKEND_H */
