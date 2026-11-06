// SPDX-License-Identifier: GPL-2.0
/*
 * mm/rswap_sock.c - TCP transport shared by the rswap KV backends
 *
 * Every rswap backend reaches its key-value store over a plain TCP stream.
 * These helpers create the connection, send a buffer completely, receive once
 * and move one page image between a folio page and the stream.  They are
 * deliberately stateless and only own the socket they are given, so the
 * connection strategy stays with the backend: HTTP/1.0 carries one object per
 * request and opens a connection for it, Redis pipelines a whole batch into
 * one round trip and keeps its connections pooled.
 *
 * The timeouts are the ones rswap_sock_connect() put on the socket, so every
 * send and receive below is bounded by the backend's send and receive
 * timeout.
 */

#define pr_fmt(fmt) "rswap: " fmt

#include <linux/bvec.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <linux/uio.h>
#include <net/sock.h>
#include <net/tcp_states.h>

#include "rswap_backend.h"

/*
 * Create a TCP socket connected to @host:@port.
 *
 * Returns the socket, or an ERR_PTR() on failure.  @host is an IPv4 literal
 * (a host name would need a resolver in the swap I/O path).
 */
struct socket *rswap_sock_connect(const char *host, u16 port,
				  unsigned int send_timeout_ms,
				  unsigned int recv_timeout_ms)
{
	struct socket *sock;
	struct sockaddr_in sin;
	long send_timeo;
	long recv_timeo;
	int ret;

	/* A zero timeout would mean "never block", which is never wanted. */
	send_timeo = max_t(long, 1, msecs_to_jiffies(send_timeout_ms));
	recv_timeo = max_t(long, 1, msecs_to_jiffies(recv_timeout_ms));

	ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP,
			       &sock);
	if (ret < 0) {
		pr_err_ratelimited("sock_create_kern failed: %d\n", ret);
		return ERR_PTR(ret);
	}

	/* Also bounds the connect wait. */
	sock_set_sndtimeo(sock->sk, send_timeo);
	WRITE_ONCE(sock->sk->sk_rcvtimeo, recv_timeo);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	if (!in4_pton(host, -1, (u8 *)&sin.sin_addr.s_addr, -1, NULL)) {
		pr_err_ratelimited("bad KV host address: %s\n", host);
		sock_release(sock);
		return ERR_PTR(-EINVAL);
	}

	ret = kernel_connect(sock, (struct sockaddr_unsized *)&sin, sizeof(sin),
			     0);
	if (ret < 0) {
		pr_err_ratelimited("kernel_connect to %s:%u failed: %d\n",
				   host, port, ret);
		sock_release(sock);
		return ERR_PTR(ret);
	}

	return sock;
}

void rswap_sock_close(struct socket *sock)
{
	kernel_sock_shutdown(sock, SHUT_RDWR);
	sock_release(sock);
}

/*
 * Is @sock still usable?  A pooled connection whose peer has closed is in
 * CLOSE_WAIT: writing to it succeeds locally, and the request is then waited
 * for until the receive timeout.  Such a socket is dropped instead of used.
 */
bool rswap_sock_alive(struct socket *sock)
{
	return sock->sk && READ_ONCE(sock->sk->sk_state) == TCP_ESTABLISHED;
}

/* Send @len bytes from @data, looping over short sends. */
int rswap_sock_send(struct socket *sock, const void *data, size_t len)
{
	struct msghdr mhdr = { .msg_flags = MSG_NOSIGNAL };
	struct kvec iov = { .iov_base = (void *)data, .iov_len = len };
	int ret;

	if (!len)
		return 0;

	while (iov.iov_len) {
		ret = kernel_sendmsg(sock, &mhdr, &iov, 1, iov.iov_len);
		if (ret <= 0)
			return ret ? ret : -EIO;
		iov.iov_base = (char *)iov.iov_base + ret;
		iov.iov_len -= ret;
	}
	return 0;
}

/* Receive between 1 and @len bytes.  Zero is reported as -ECONNRESET. */
int rswap_sock_recv(struct socket *sock, void *buf, size_t len)
{
	struct msghdr mhdr = { .msg_flags = MSG_NOSIGNAL };
	struct kvec iov = { .iov_base = buf, .iov_len = len };
	int ret;

	ret = kernel_recvmsg(sock, &mhdr, &iov, 1, len, 0);
	if (!ret)
		return -ECONNRESET;
	return ret;
}

/*
 * Send the @len bytes described by @bvecs, looping over short sends.
 *
 * iterate_bvec() maps one segment at a time for the duration of a copy, so a
 * page image is never mapped across the blocking call.
 */
int rswap_sock_send_bvecs(struct socket *sock, struct bio_vec *bvecs,
			  unsigned int nr, size_t len)
{
	struct msghdr msg = { .msg_flags = MSG_NOSIGNAL };
	int ret;

	if (!len)
		return 0;

	iov_iter_bvec(&msg.msg_iter, ITER_SOURCE, bvecs, nr, len);
	while (iov_iter_count(&msg.msg_iter)) {
		ret = sock_sendmsg(sock, &msg);
		if (ret <= 0)
			return ret ? ret : -EIO;
	}
	return 0;
}

/* Send exactly one page image of @len bytes from @page. */
int rswap_sock_send_page(struct socket *sock, struct page *page, size_t len)
{
	struct bio_vec bv;

	bvec_set_page(&bv, page, len, 0);
	return rswap_sock_send_bvecs(sock, &bv, 1, len);
}

/* Receive exactly one page image of @len bytes into @page. */
int rswap_sock_recv_page(struct socket *sock, struct page *page, size_t len)
{
	struct msghdr msg = { };
	struct bio_vec bv;
	int ret;

	if (!len)
		return 0;

	bvec_set_page(&bv, page, len, 0);
	iov_iter_bvec(&msg.msg_iter, ITER_DEST, &bv, 1, len);
	while (iov_iter_count(&msg.msg_iter)) {
		ret = sock_recvmsg(sock, &msg, 0);
		if (ret <= 0)
			return ret ? ret : -ECONNRESET;
	}
	return 0;
}
