// SPDX-License-Identifier: GPL-2.0-only
/*
 * tools/mm/kvswap_server.c - Simple HTTP KV store for rswap
 *
 * A minimal HTTP/1.0 server that stores and retrieves key-value pairs
 * where keys are SHA-256 hex strings and values are arbitrary byte
 * sequences (typically swap page data).
 *
 * Usage:
 *   kvswap_server [-d <data_dir>] [-p <port>] [-l <listen_addr>]
 *
 * Defaults:
 *   data_dir  = /tmp/rswap-kv
 *   port      = 6789
 *   listen    = 127.0.0.1
 *
 * Endpoints:
 *   GET  /v1/folios/<sha256>/read   -> 200 with body, or 404
 *   POST /v1/folios/<sha256>/write  -> 200 on success
 *
 * The server stores one file per key in <data_dir>/<sha256>.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>
#include <limits.h>
#include <ctype.h>

/* ---------- Configuration ---------- */

#define DEFAULT_PORT	6789
#define DEFAULT_ADDR	"127.0.0.1"
#define DEFAULT_DIR	"/tmp/rswap-kv"
#define MAX_BACKLOG	128
#define MAX_HEADER	8192
#define MAX_PATH	PATH_MAX
#define SHA256_HEXLEN	64
#define MAX_BODY		(64UL * 1024 * 1024)

/* Global config, set from cmdline. */
static struct {
	int		port;
	char		listen_addr[64];
	char		data_dir[MAX_PATH];
} cfg = {
	.port	= DEFAULT_PORT,
	.listen_addr = DEFAULT_ADDR,
	.data_dir = DEFAULT_DIR,
};

/* ---------- Utilities ---------- */

static void die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

/* Build the file path for a given SHA-256 hex key. */
static int key_to_path(const char *sha256, char *out, size_t outsz)
{
	size_t len;
	const char *p;

	/* Validate: exactly 64 hex chars. */
	for (len = 0, p = sha256; *p; p++, len++) {
		if (!isxdigit((unsigned char)*p))
			return -1;
	}
	if (len != SHA256_HEXLEN)
		return -1;

	return snprintf(out, outsz, "%s/%.2s/%s",
			cfg.data_dir, sha256, sha256) < (int)outsz ? 0 : -1;
}

/* Ensure the storage directory and its 2-char subdir exist. */
static int ensure_dirs(const char *sha256)
{
	char sub[MAX_PATH];
	int ret;

	/* Create top-level data dir. */
	ret = mkdir(cfg.data_dir, 0755);
	if (ret && errno != EEXIST)
		return -errno;

	/* Create 2-char prefix subdirectory. */
	ret = snprintf(sub, sizeof(sub), "%s/%.2s", cfg.data_dir, sha256);
	if (ret >= (int)sizeof(sub))
		return -ENAMETOOLONG;

	ret = mkdir(sub, 0755);
	if (ret && errno != EEXIST)
		return -errno;

	return 0;
}

/* ---------- HTTP response helpers ---------- */

static int write_all(int fd, const void *data, size_t len)
{
	const char *p = data;

	while (len) {
		ssize_t n = write(fd, p, len);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;
		p += n;
		len -= n;
	}
	return 0;
}

static void send_200(int fd, const void *body, size_t bodylen)
{
	char hdr[256];
	int n;

	n = snprintf(hdr, sizeof(hdr),
		     "HTTP/1.0 200 OK\r\n"
		     "Content-Length: %zu\r\n"
		     "Content-Type: application/octet-stream\r\n"
		     "Connection: close\r\n"
		     "\r\n",
		     bodylen);
	if (write_all(fd, hdr, n) == 0 && body && bodylen > 0)
		write_all(fd, body, bodylen);
}

static void send_404(int fd)
{
	static const char msg[] =
		"HTTP/1.0 404 Not Found\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"\r\n";
	write_all(fd, msg, sizeof(msg) - 1);
}

static void send_400(int fd)
{
	static const char msg[] =
		"HTTP/1.0 400 Bad Request\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"\r\n";
	write_all(fd, msg, sizeof(msg) - 1);
}

static void send_500(int fd)
{
	static const char msg[] =
		"HTTP/1.0 500 Internal Server Error\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"\r\n";
	write_all(fd, msg, sizeof(msg) - 1);
}

/* ---------- Request parsing ---------- */

/*
 * Parse a line like:
 *   GET /v1/folios/<sha256>/read HTTP/1.0\r\n
 *   POST /v1/folios/<sha256>/write HTTP/1.0\r\n
 *
 * Extracts method, sha256, and operation ("read" or "write").
 */
static int parse_request(const char *buf,
			  char *method, size_t method_sz __attribute__((__unused__)),
			  char *sha256, size_t sha256_sz __attribute__((__unused__)),
			  char *op, size_t op_sz)
{
	char path[512];
	char proto[16];
	int n;

	n = sscanf(buf, "%16s %511s %15s", method, path, proto);
	if (n != 3)
		return -1;

	/* Path: /v1/folios/<64 hex chars>/<read|write> */
	if (strncmp(path, "/v1/folios/", 11) != 0)
		return -1;

	const char *p = path + 11;
	const char *slash = strchr(p, '/');
	if (!slash)
		return -1;

	size_t keylen = slash - p;
	if (keylen != SHA256_HEXLEN)
		return -1;

	memcpy(sha256, p, SHA256_HEXLEN);
	sha256[SHA256_HEXLEN] = '\0';

	/* Validate hex. */
	for (n = 0; n < SHA256_HEXLEN; n++) {
		if (!isxdigit((unsigned char)sha256[n]))
			return -1;
	}

	snprintf(op, op_sz, "%s", slash + 1);

	return 0;
}

/* ---------- Request handlers ---------- */

static void handle_get(int fd, const char *sha256)
{
	char fpath[MAX_PATH];
	struct stat st;
	int f;
	void *map;

	if (key_to_path(sha256, fpath, sizeof(fpath)) < 0) {
		send_400(fd);
		return;
	}

	f = open(fpath, O_RDONLY);
	if (f < 0) {
		send_404(fd);
		return;
	}

	if (fstat(f, &st) < 0 || st.st_size < 0 ||
	    (unsigned long long)st.st_size > MAX_BODY) {
		close(f);
		send_500(fd);
		return;
	}

	map = malloc(st.st_size ? st.st_size : 1);
	if (!map) {
		close(f);
		send_500(fd);
		return;
	}

	if (st.st_size > 0) {
		size_t total = 0;

		while (total < (size_t)st.st_size) {
			ssize_t n = read(f, (char *)map + total,
					 st.st_size - total);

			if (n < 0 && errno == EINTR)
				continue;
			if (n <= 0) {
				free(map);
				close(f);
				send_500(fd);
				return;
			}
			total += n;
		}
	}
	close(f);

	send_200(fd, map, st.st_size);
	free(map);
}

static void handle_post(int fd, const char *sha256,
			const char *body, size_t bodylen)
{
	char fpath[MAX_PATH];
	char temporary[MAX_PATH];
	int f;

	if (ensure_dirs(sha256) < 0) {
		send_500(fd);
		return;
	}

	if (key_to_path(sha256, fpath, sizeof(fpath)) < 0) {
		send_400(fd);
		return;
	}

	if (snprintf(temporary, sizeof(temporary), "%s.XXXXXX", fpath) >=
	    (int)sizeof(temporary)) {
		send_500(fd);
		return;
	}
	f = mkstemp(temporary);
	if (f < 0) {
		send_500(fd);
		return;
	}

	/* Publish only complete values; a failed update keeps the old value. */
	if (write_all(f, body, bodylen) < 0) {
		close(f);
		unlink(temporary);
		send_500(fd);
		return;
	}

	if (close(f) < 0 || rename(temporary, fpath) < 0) {
		unlink(temporary);
		send_500(fd);
		return;
	}
	send_200(fd, NULL, 0);
}

/* ---------- Connection handler (single thread) ---------- */

static void handle_connection(int fd)
{
	char buf[MAX_HEADER];
	char method[32], sha256[SHA256_HEXLEN + 1], op[32];
	ssize_t n;
	const char *body = NULL;
	size_t bodylen = 0;
	size_t total = 0;
	char *payload = NULL;
	char *header_end;
	struct timeval timeout = { .tv_sec = 5 };

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
		       &timeout, sizeof(timeout)) < 0 ||
	    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
		       &timeout, sizeof(timeout)) < 0)
		goto done;
	/* TCP may split the header, body, or both across arbitrary reads. */
	for (;;) {
		if (total == sizeof(buf) - 1) {
			send_400(fd);
			goto done;
		}
		n = read(fd, buf + total, sizeof(buf) - 1 - total);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			goto done;
		total += n;
		buf[total] = '\0';
		header_end = strstr(buf, "\r\n\r\n");
		if (header_end)
			break;
	}
	*header_end = '\0';		/* terminate header at blank line */
	body = header_end + 4;
	bodylen = total - (body - buf);

	/* Parse the request line. */
	if (parse_request(buf, method, sizeof(method),
			  sha256, sizeof(sha256),
			  op, sizeof(op)) < 0) {
		send_400(fd);
		goto done;
	}

	if (strcmp(method, "GET") == 0 && strcmp(op, "read") == 0) {
		handle_get(fd, sha256);
	} else if (strcmp(method, "POST") == 0 && strcmp(op, "write") == 0) {
		char *line = strstr(buf, "\r\n");
		size_t content_length = 0;
		int have_length = 0;

		while (line) {
			char *next;

			line += 2;
			next = strstr(line, "\r\n");
			if (next)
				*next = '\0';
			if (!strncasecmp(line, "Content-Length:", 15)) {
				char *end;
				unsigned long long length;

				line += 15;
				while (*line == ' ' || *line == '\t')
					line++;
				errno = 0;
				length = strtoull(line, &end, 10);
				while (*end == ' ' || *end == '\t')
					end++;
				if (have_length || !isdigit((unsigned char)*line) ||
				    end == line || *end || errno ||
				    length > MAX_BODY) {
					send_400(fd);
					goto done;
				}
				content_length = length;
				have_length = 1;
			} else if (!strncasecmp(line, "Transfer-Encoding:", 18)) {
				send_400(fd);
				goto done;
			}
			line = next;
		}
		if (!have_length || bodylen > content_length) {
			send_400(fd);
			goto done;
		}
		payload = malloc(content_length ? content_length : 1);
		if (!payload) {
			send_500(fd);
			goto done;
		}
		memcpy(payload, body, bodylen);
		while (bodylen < content_length) {
			n = read(fd, payload + bodylen, content_length - bodylen);
			if (n < 0 && errno == EINTR)
				continue;
			if (n <= 0) {
				send_400(fd);
				goto done;
			}
			bodylen += n;
		}
		handle_post(fd, sha256, payload, content_length);
	} else {
		send_400(fd);
	}

done:
	free(payload);
	close(fd);
}

/* ---------- Server main loop ---------- */

static volatile int server_running = 1;

static void sigint_handler(int sig)
{
	(void)sig;
	server_running = 0;
}

static int create_listener(void)
{
	struct sockaddr_in addr;
	int fd, optval = 1;
	int ret;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		die("socket: %s\n", strerror(errno));

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
		die("setsockopt(SO_REUSEADDR): %s", strerror(errno));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(cfg.port);
	if (inet_pton(AF_INET, cfg.listen_addr, &addr.sin_addr) <= 0)
		die("inet_pton(%s): %s", cfg.listen_addr, strerror(errno));

	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0)
		die("bind(%s:%d): %s", cfg.listen_addr, cfg.port, strerror(errno));

	ret = listen(fd, MAX_BACKLOG);
	if (ret < 0)
		die("listen: %s", strerror(errno));

	return fd;
}

static void print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-d <data_dir>] [-p <port>] [-l <listen_addr>]\n"
		"\n"
		"Default data_dir: %s\n"
		"Default port:     %d\n"
		"Default listen:   %s\n",
		prog, DEFAULT_DIR, DEFAULT_PORT, DEFAULT_ADDR);
}

int main(int argc, char **argv)
{
	int opt, listen_fd;

	while ((opt = getopt(argc, argv, "d:p:l:h")) != -1) {
		switch (opt) {
		case 'd':
			if (strlen(optarg) >= sizeof(cfg.data_dir))
				die("data_dir too long");
			strncpy(cfg.data_dir, optarg, sizeof(cfg.data_dir) - 1);
			cfg.data_dir[sizeof(cfg.data_dir) - 1] = '\0';
			/* Strip trailing slash. */
			size_t dlen = strlen(cfg.data_dir);
			while (dlen > 1 && cfg.data_dir[dlen - 1] == '/')
				cfg.data_dir[--dlen] = '\0';
			break;
		case 'p':
			cfg.port = atoi(optarg);
			if (cfg.port <= 0 || cfg.port > 65535)
				die("invalid port: %s", optarg);
			break;
		case 'l':
			if (strlen(optarg) >= sizeof(cfg.listen_addr))
				die("listen address too long");
			strncpy(cfg.listen_addr, optarg,
				sizeof(cfg.listen_addr) - 1);
			cfg.listen_addr[sizeof(cfg.listen_addr) - 1] = '\0';
			break;
		case 'h':
		default:
			print_usage(argv[0]);
			exit(opt == 'h' ? 0 : 1);
		}
	}

	fprintf(stderr, "kvswap_server: listening on %s:%d, data in %s\n",
		cfg.listen_addr, cfg.port, cfg.data_dir);

	/* Ignore SIGPIPE so write() failures return EPIPE. */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, sigint_handler);

	listen_fd = create_listener();

	while (server_running) {
		int client_fd;
		struct sockaddr_in client_addr;
		socklen_t addrlen = sizeof(client_addr);

		/* Accept with a timeout so we can check server_running. */
		struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(listen_fd, &rfds);
		int ret = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (ret == 0)
			continue;

		client_fd = accept(listen_fd,
				   (struct sockaddr *)&client_addr, &addrlen);
		if (client_fd < 0) {
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			break;
		}

		handle_connection(client_fd);
	}

	close(listen_fd);
	fprintf(stderr, "kvswap_server: shutting down\n");
	return 0;
}
