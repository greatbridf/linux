// SPDX-License-Identifier: GPL-2.0
/*
 * mm/rswap_sock.c - TCP transport shared by the rswap KV backends
 *
 * Every rswap backend reaches its key-value store over a plain TCP stream.
 * These helpers create the connection, send a buffer completely, and receive
 * once.  They are deliberately stateless: a backend opens a connection per
 * page operation, so the swap I/O path needs no locks and no connection
 * state of its own.
 */

#define pr_fmt(fmt) "rswap: " fmt

#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <linux/uio.h>
#include <net/sock.h>

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
