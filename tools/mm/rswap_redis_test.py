#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the rswap Redis backend against a scripted and a real server.

The C harness is built from the actual RESP client code in mm/rswap_redis.c:
the wire format and backend operation sections are extracted verbatim and
linked against POSIX socket shims instead of kernel sockets.  Everything the
kernel would do -- pipelining AUTH/SELECT/SET, reading status and bulk
replies, mapping errors -- is therefore the code under test.

By default the harness runs against a scripted RESP server in this process,
which needs no network and no credentials.  --live runs the same harness
against a real Redis server and additionally checks, out of band, that the
page really is stored under the userspace SHA-256 hex key:

  python3 tools/mm/rswap_redis_test.py
  python3 tools/mm/rswap_redis_test.py --live --host 127.0.0.1 \\
      --port 6379 --password "$RSWAP_REDIS_PASSWORD" --db 0
"""

import argparse
import errno
import hashlib
import os
import pathlib
import re
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading

PAGE_SIZE = 4096
EACCES = errno.EACCES
EMSGSIZE = errno.EMSGSIZE
ENOENT = errno.ENOENT

SHIMS = r"""
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define RSWAP_KV_HOST_LEN 64
#define RSWAP_KV_KEY_LEN 97
#define RSWAP_HASH_LEN 48
#define RSWAP_BATCH_MAX 32
#define __init
#define GFP_NOIO 0
#define GFP_KERNEL 0
#define __GFP_ZERO 0
#define WARN_ON_ONCE(cond) (cond)
#define PAGE_SIZE 4096
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#define IS_ERR(ptr) ((uintptr_t)(ptr) > (uintptr_t)-4096)
#define PTR_ERR(ptr) ((long)(ptr))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define offset_in_page(p) ((unsigned long)(p) & (PAGE_SIZE - 1))
/*
 * The harness has no clock, so every request gets the far-future deadline
 * below: rswap_sock_deadline() returns it and it never expires.
 */
#define RSWAP_SHIM_DEADLINE ((unsigned long)-1)

struct socket { int fd; };

/*
 * One base page image.  The kernel moves page contents through struct page, so
 * the shim keeps the image in @data and every transport helper below moves
 * bytes between that buffer and the stub socket.
 */
struct page { unsigned char *data; };
/* The wire fragments of the common RESP parts live in one folio-sized buffer. */
struct folio { unsigned char *data; };
struct bio_vec {
    struct folio *folio;
    struct page *bv_page;
    size_t bv_len;
    size_t bv_offset;
};
struct iov_iter { int unused; };

struct rswap_kv_page {
    const char *key;
    struct page *page;
};
static struct socket socket_stub;

#define kvmalloc(size, flags) malloc(size)
#define kvfree(ptr) free(ptr)

static void *kmap_local_page(struct page *page)
{
    return page->data;
}
static void kunmap_local(void *address) { }

static struct folio *folio_alloc(int gfp, unsigned int order)
{
    struct folio *folio = calloc(1, sizeof(*folio));

    if (folio)
        folio->data = calloc(1, (size_t)PAGE_SIZE << order);
    return folio;
}
static char *folio_address(const struct folio *folio)
{
    return (char *)folio->data;
}
static void folio_put(struct folio *folio)
{
    free(folio->data);
    free(folio);
}
static void memzero_explicit(void *data, size_t len)
{
    memset(data, 0, len);
}
static bool is_vmalloc_addr(const void *addr)
{
    return false;
}
static struct page *vmalloc_to_page(const void *addr)
{
    return NULL;            /* is_vmalloc_addr() is false in this harness */
}

/*
 * virt_to_page() of a kernel buffer: the shim has no page tables, so @data of
 * the returned page is the page-aligned base address of the buffer and the bvec
 * offset added to it addresses the same bytes again.  One batch builds a few
 * dozen such bvecs and they are all sent before the pool wraps.
 */
#define SHIM_BUFFER_PAGES 512
static struct page buffer_pages[SHIM_BUFFER_PAGES];
static unsigned int buffer_page_next;
static struct page *virt_to_page(const void *addr)
{
    struct page *page = &buffer_pages[buffer_page_next++ % SHIM_BUFFER_PAGES];

    page->data = (unsigned char *)((uintptr_t)addr & ~(PAGE_SIZE - 1));
    return page;
}

static void bvec_set_page(struct bio_vec *bv, struct page *page, size_t len,
                          size_t offset)
{
    bv->folio = NULL;
    bv->bv_page = page;
    bv->bv_len = len;
    bv->bv_offset = offset;
}
static void bvec_set_folio(struct bio_vec *bv, struct folio *folio, size_t len,
                           size_t offset)
{
    bv->folio = folio;
    bv->bv_page = NULL;
    bv->bv_len = len;
    bv->bv_offset = offset;
}
static const unsigned char *rswap_shim_bvec_data(const struct bio_vec *bv)
{
    if (bv->bv_page)
        return bv->bv_page->data + bv->bv_offset;
    return bv->folio->data + bv->bv_offset;
}

/* Pool primitives: the harness runs one operation at a time. */
typedef struct { long long v; } atomic64_t;
#define atomic64_read(p) ((p)->v)
#define atomic64_inc(p) ((p)->v++)
struct mutex { int unused; };
#define DEFINE_MUTEX(name) struct mutex name
#define mutex_lock(m) do { (void)(m); } while (0)
#define mutex_unlock(m) do { (void)(m); } while (0)
struct semaphore { int count; };
#define DEFINE_SEMAPHORE(name, n) struct semaphore name = { .count = (n) }
static void down(struct semaphore *sem) { sem->count--; }
static void up(struct semaphore *sem) { sem->count++; }

/* One command buffer per pooled connection, as mempool_create_kmalloc_pool(). */
struct mempool { size_t size; };
static struct mempool *mempool_create_kmalloc_pool(unsigned int min_nr,
                                                   size_t size)
{
    struct mempool *pool = calloc(1, sizeof(*pool));

    if (pool)
        pool->size = size;
    return pool;
}
static void *mempool_alloc(struct mempool *pool, int gfp)
{
    return calloc(1, pool->size);
}
static void mempool_free(void *element, struct mempool *pool)
{
    free(element);
}

/* Mirrors the private state the backend keeps above the extracted code. */
static struct {
    char host[RSWAP_KV_HOST_LEN];
    unsigned short port;
    char user[RSWAP_KV_HOST_LEN];
    char password[128];
    unsigned int db;
    unsigned int send_timeout_ms;
    unsigned int recv_timeout_ms;
} rswap_redis;

/* Mirrors kstrtol(): no leading whitespace, optional sign, no trailing junk. */
static int kstrtol(const char *text, unsigned int base, long *out)
{
    char *end;
    if (!text || !*text || *text == ' ' || *text == '\t')
        return -EINVAL;
    errno = 0;
    *out = strtol(text, &end, base);
    return errno || end == text || *end ? -EINVAL : 0;
}

static int scnprintf(char *buf, size_t size, const char *fmt, ...)
{
    va_list args;
    int len;

    va_start(args, fmt);
    len = vsnprintf(buf, size, fmt, args);
    va_end(args);
    if (len < 0)
        return len;
    return (size_t)len < size ? len : (int)size - 1;
}

/* ---------- Stub transport ---------- */

static struct socket *rswap_sock_connect(const char *host, unsigned short port,
                                         unsigned int connect_timeout_ms,
                                         unsigned int send_timeout_ms,
                                         unsigned int recv_timeout_ms)
{
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    struct timeval send_timeo = { .tv_sec = send_timeout_ms / 1000 };
    struct timeval recv_timeo = { .tv_sec = recv_timeout_ms / 1000 };
    int fd;

    if (inet_pton(AF_INET, host, &sin.sin_addr) != 1)
        return (struct socket *)(intptr_t)-EINVAL;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return (struct socket *)(intptr_t)-errno;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &send_timeo, sizeof(send_timeo));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &recv_timeo, sizeof(recv_timeo));
    if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        int saved = errno;
        close(fd);
        return (struct socket *)(intptr_t)-saved;
    }
    socket_stub.fd = fd;
    return &socket_stub;
}

static void rswap_sock_close(struct socket *sock)
{
    close(sock->fd);
    sock->fd = -1;
}

static bool rswap_sock_alive(struct socket *sock)
{
    return sock->fd >= 0;
}

static unsigned long rswap_sock_deadline(unsigned int timeout_ms)
{
    return RSWAP_SHIM_DEADLINE;
}

static bool rswap_sock_expired(unsigned long deadline)
{
    return deadline != RSWAP_SHIM_DEADLINE;
}

static int send_all(struct socket *sock, const void *data, size_t len)
{
    const char *cursor = data;

    while (len) {
        ssize_t done = send(sock->fd, cursor, len, 0);
        if (done <= 0)
            return done ? -errno : -EIO;
        cursor += done;
        len -= done;
    }
    return 0;
}

static int recv_all(struct socket *sock, void *data, size_t len)
{
    char *cursor = data;

    while (len) {
        ssize_t done = recv(sock->fd, cursor, len, 0);
        if (!done)
            return -ECONNRESET;
        if (done < 0)
            return -errno;
        cursor += done;
        len -= done;
    }
    return 0;
}

static int rswap_sock_send(struct socket *sock, const void *data, size_t len,
                           unsigned long deadline)
{
    if (rswap_sock_expired(deadline))
        return -ETIMEDOUT;
    return send_all(sock, data, len);
}

static int rswap_sock_send_bvecs(struct socket *sock, struct bio_vec *bvecs,
                                 unsigned int nr, size_t len,
                                 unsigned long deadline)
{
    size_t total = 0;
    unsigned int i;
    int ret;

    if (rswap_sock_expired(deadline))
        return -ETIMEDOUT;
    for (i = 0; i < nr; i++) {
        ret = send_all(sock, rswap_shim_bvec_data(&bvecs[i]),
                       bvecs[i].bv_len);
        if (ret)
            return ret;
        total += bvecs[i].bv_len;
    }
    return total == len ? 0 : -EINVAL;
}

static int rswap_sock_send_page(struct socket *sock, struct page *page,
                                size_t len, unsigned long deadline)
{
    if (rswap_sock_expired(deadline))
        return -ETIMEDOUT;
    return send_all(sock, page->data, len);
}

static int rswap_sock_recv_page(struct socket *sock, struct page *page,
                                size_t off, size_t len,
                                unsigned long deadline)
{
    if (rswap_sock_expired(deadline))
        return -ETIMEDOUT;
    return recv_all(sock, page->data + off, len);
}

/* Buffered reads return the byte count, as the kernel helper does. */
static int rswap_sock_recv(struct socket *sock, void *buf, size_t len)
{
    ssize_t done = recv(sock->fd, buf, len, 0);

    if (!done)
        return -ECONNRESET;
    return done < 0 ? -errno : done;
}
"""

MAIN = r"""
/* Deterministic page image, also computed by the Python side. */
static void fill_page(unsigned char *page, const char *key)
{
    unsigned int seed = 2166136261u;
    size_t i;

    for (i = 0; key[i]; i++) {
        seed ^= (unsigned char)key[i];
        seed *= 16777619u;
    }
    for (i = 0; i < PAGE_SIZE; i++) {
        seed = seed * 1103515245u + 12345u;
        page[i] = (seed >> 16) & 0xff;
    }
}

/*
 * Batch keys: the last two hex digits of @key select the page, so every key of
 * the batch is still a full RSWAP_KV_KEY_LEN - 1 digit digest.
 */
static void batch_key(char *out, const char *key, unsigned int index)
{
    static const char hex[] = "0123456789abcdef";

    strcpy(out, key);
    out[RSWAP_KV_KEY_LEN - 3] = hex[index >> 4];
    out[RSWAP_KV_KEY_LEN - 2] = hex[index & 15];
}

int main(int argc, char **argv)
{
    unsigned char page[PAGE_SIZE];
    static unsigned char batch[RSWAP_BATCH_MAX][PAGE_SIZE];
    /* One base page image per batch entry, as the core hands them over. */
    static struct page images[RSWAP_BATCH_MAX];
    struct page image = { .data = page };
    char keys[RSWAP_BATCH_MAX][RSWAP_KV_KEY_LEN];   /* hex digest plus NUL */
    struct rswap_kv_page pages[RSWAP_BATCH_MAX];
    const char *command, *key;
    unsigned int i;
    int ret;

    if (argc != 8) {
        fprintf(stderr, "usage: %s host port user password db cmd key\n",
                argv[0]);
        return 2;
    }
    snprintf(rswap_redis.host, sizeof(rswap_redis.host), "%s", argv[1]);
    rswap_redis.port = atoi(argv[2]);
    snprintf(rswap_redis.user, sizeof(rswap_redis.user), "%s", argv[3]);
    snprintf(rswap_redis.password, sizeof(rswap_redis.password), "%s",
             argv[4]);
    rswap_redis.db = atoi(argv[5]);
    rswap_redis.send_timeout_ms = 5000;
    rswap_redis.recv_timeout_ms = 5000;
    command = argv[6];
    key = argv[7];
    /* The wire fragments and the command pool: the real backend init. */
    ret = rswap_redis_init_parts();
    if (ret) {
        fprintf(stderr, "rswap_redis_init_parts failed: %d\n", ret);
        return 2;
    }

    fill_page(page, key);
    pages[0].key = key;
    pages[0].page = &image;
    if (!strcmp(command, "put") || !strcmp(command, "put-noauth")) {
        int expected = strcmp(command, "put") ? -EACCES : 0;

        ret = rswap_redis_store(pages, 1, sizeof(page));
        printf("store ret=%d\n", ret);
        return ret == expected ? 0 : 1;
    }
    if (!strcmp(command, "get")) {
        unsigned char actual[PAGE_SIZE];
        struct page got = { .data = actual };

        memset(actual, 0, sizeof(actual));
        pages[0].page = &got;
        ret = rswap_redis_load(pages, 1, sizeof(actual));
        printf("load ret=%d match=%d\n", ret,
               ret ? 0 : !memcmp(page, actual, sizeof(page)));
        return ret || memcmp(page, actual, sizeof(page)) ? 1 : 0;
    }
    if (!strcmp(command, "putbatch") || !strcmp(command, "getbatch")) {
        int batch_ret = 0, match = 1;

        for (i = 0; i < RSWAP_BATCH_MAX; i++) {
            batch_key(keys[i], key, i);
            fill_page(batch[i], keys[i]);
            images[i].data = batch[i];
            pages[i].key = keys[i];
            pages[i].page = &images[i];
        }
        if (!strcmp(command, "putbatch"))
            batch_ret = rswap_redis_store(pages, RSWAP_BATCH_MAX, PAGE_SIZE);
        else
            batch_ret = rswap_redis_load(pages, RSWAP_BATCH_MAX, PAGE_SIZE);
        for (i = 0; i < RSWAP_BATCH_MAX; i++) {
            unsigned char expected[PAGE_SIZE];

            fill_page(expected, keys[i]);
            match &= !memcmp(batch[i], expected, PAGE_SIZE);
        }
        printf("batch ret=%d match=%d\n", batch_ret, match);
        return batch_ret || !match ? 1 : 0;
    }
    if (!strcmp(command, "pooltest")) {
        int pool_ret = 0, batch_no;

        for (batch_no = 0; batch_no < 4 && !pool_ret; batch_no++) {
            for (i = 0; i < 8; i++) {
                batch_key(keys[i], key, i);
                keys[i][RSWAP_KV_KEY_LEN - 3] = '0' + batch_no;
                fill_page(batch[i], keys[i]);
                images[i].data = batch[i];
                pages[i].key = keys[i];
                pages[i].page = &images[i];
            }
            pool_ret = rswap_redis_store(pages, 8, PAGE_SIZE);
            if (!pool_ret)
                pool_ret = rswap_redis_load(pages, 8, PAGE_SIZE);
        }
        printf("pool ret=%d\n", pool_ret);
        return pool_ret ? 1 : 0;
    }
    if (!strcmp(command, "get-missing")) {
        ret = rswap_redis_load(pages, 1, sizeof(page));
        printf("load ret=%d\n", ret);
        return ret == -ENOENT ? 0 : 1;
    }
    if (!strcmp(command, "get-badlen")) {
        ret = rswap_redis_load(pages, 1, sizeof(page));
        printf("load ret=%d\n", ret);
        return ret == -EMSGSIZE ? 0 : 1;
    }
    fprintf(stderr, "unknown command %s\n", command);
    return 2;
}
"""


def digest_key(label):
    """A 48-byte program-supplied digest, hex encoded as the kernel key."""
    return hashlib.sha384(label).hexdigest()


def page_bytes(key):
    """The same deterministic page image the C harness builds."""
    seed = 2166136261
    for byte in key.encode():
        seed = ((seed ^ byte) * 16777619) & 0xFFFFFFFF
    out = bytearray(PAGE_SIZE)
    for i in range(PAGE_SIZE):
        seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
        out[i] = (seed >> 16) & 0xFF
    return bytes(out)


def extract(text, start, end, what):
    """The code between two markers; a missing marker is an error."""
    begin = text.find(start)
    if begin < 0:
        raise SystemExit(f"error: {what}: start marker {start!r} not found")
    stop = text.find(end, begin)
    if stop < 0:
        raise SystemExit(f"error: {what}: end marker {end!r} not found")
    return text[begin:stop]


def define_value(text, name, where):
    match = re.search(r"^#define\s+%s\s+(.+)$" % re.escape(name), text,
                      re.MULTILINE)
    if not match:
        raise SystemExit(f"error: {where}: #define {name} not found")
    return match.group(1).strip()


def define_number(text, name, where, known):
    """Evaluate a #define that may be an arithmetic expression."""
    expression = re.sub(r"/\*.*?\*/", "", define_value(text, name, where))
    try:
        return int(eval(expression, {}, dict(known)))
    except (NameError, SyntaxError, TypeError):
        raise SystemExit(f"error: {where}: cannot evaluate {name} "
                         f"({expression!r})")


def struct_members(text, name, where):
    """Member names of a one-line-per-member struct definition."""
    match = re.search(r"^struct\s+%s\s*\{(.*?)^\};" % re.escape(name), text,
                      re.MULTILINE | re.DOTALL)
    if not match:
        raise SystemExit(f"error: {where}: struct {name} not found")
    members = []
    for line in match.group(1).splitlines():
        line = re.sub(r"/\*.*?\*/", "", line).strip()
        if not line:
            continue
        member = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(\[[^]]*\])?\s*;",
                           line)
        if not member:
            raise SystemExit(f"error: {where}: cannot parse {name} member "
                             f"{line!r}")
        members.append(member.group(1))
    return members


def check_shim_drift(root):
    """Fail when a shim no longer matches the kernel sources it stands for."""
    backend_h = (root / "mm/rswap_backend.h").read_text()
    rswap_h = (root / "mm/rswap.h").read_text()
    redis_c = (root / "mm/rswap_redis.c").read_text()
    # The wire constants and the request deadline are extracted, not shimmed.
    extract(redis_c, "#define RSWAP_REDIS_MAX_LINE", "static struct {",
            "mm/rswap_redis.c: wire constants")
    extract(redis_c, "static unsigned long rswap_redis_deadline(void)",
            "/* ---------- RESP wire format ---------- */",
            "mm/rswap_redis.c: request deadline")
    hash_len = define_number(rswap_h, "RSWAP_HASH_LEN", "mm/rswap.h", {})
    known = {"RSWAP_HASH_LEN": hash_len}
    real = {
        "RSWAP_HASH_LEN": hash_len,
        "RSWAP_KV_HOST_LEN": define_number(backend_h, "RSWAP_KV_HOST_LEN",
                                          "mm/rswap_backend.h", known),
        "RSWAP_KV_KEY_LEN": define_number(backend_h, "RSWAP_KV_KEY_LEN",
                                         "mm/rswap_backend.h", known),
        "RSWAP_BATCH_MAX": define_number(backend_h, "RSWAP_BATCH_MAX",
                                        "mm/rswap_backend.h", known),
    }
    drift = 0
    for name, value in real.items():
        shim = define_number(SHIMS, name, "redis shims", known)
        if shim != value:
            print(f"FAIL: redis shim define {name} is {shim}, kernel says "
                  f"{value}")
            drift += 1
    want = struct_members(backend_h, "rswap_kv_page", "mm/rswap_backend.h")
    got = struct_members(SHIMS, "rswap_kv_page", "redis shims")
    if want != got:
        print(f"FAIL: redis shim struct rswap_kv_page has members {got}, "
              f"mm/rswap_backend.h has {want}")
        drift += 1
    if drift:
        return drift
    print("PASS: shim constants and structs match the kernel sources")
    return 0


def build_harness(root, directory):
    source = (root / "mm/rswap_redis.c").read_text()
    body = extract(source, "#define RSWAP_REDIS_DEFAULT_HOST", "static struct {",
                   "mm/rswap_redis.c: wire constants")
    body += extract(source, "static unsigned long rswap_redis_deadline(void)",
                    "/* ---------- RESP wire format ---------- */",
                    "mm/rswap_redis.c: request deadline")
    body += extract(source, "/* ---------- RESP wire format ---------- */",
                    "/* ---------- Backend registration ---------- */",
                    "mm/rswap_redis.c: RESP client")
    # The common wire fragments and the command pool are built by the real
    # init path, so the bytes on the wire here are the ones the kernel sends.
    body += extract(source, "static int __init rswap_redis_init_parts(",
                    "static int __init rswap_redis_init("
                    "const struct rswap_kv_config",
                    "mm/rswap_redis.c: init parts")
    path = pathlib.Path(directory) / "redis_harness.c"
    path.write_text(SHIMS + body + MAIN)
    executable = path.with_suffix("")
    subprocess.run(["cc", "-O2", "-Wall", "-Werror",
                    "-Wno-unused-function", "-Wno-unused-parameter",
                    str(path), "-o", str(executable)], check=True)
    return executable


class FakeRedisHandler(socketserver.StreamRequestHandler):
    """Minimal RESP2 server: AUTH, SELECT, SET, GET, DEL, PING."""

    def read_command(self):
        line = self.rfile.readline()
        if not line:
            return None
        if not line.startswith(b"*"):
            raise ValueError(f"bad RESP array header {line!r}")
        argv = []
        for _ in range(int(line[1:])):
            header = self.rfile.readline()
            if not header.startswith(b"$"):
                raise ValueError(f"bad bulk header {header!r}")
            argv.append(self.rfile.read(int(header[1:]) + 2)[:-2])
        return argv

    def reply(self, data):
        self.wfile.write(data)
        self.wfile.flush()

    def status(self, text):
        self.reply(b"+" + text + b"\r\n")

    def error(self, text):
        if isinstance(text, str):
            text = text.encode()
        self.reply(b"-" + text + b"\r\n")

    def handle(self):
        try:
            self.serve()
        except (BrokenPipeError, ConnectionResetError):
            pass		# the client gave up on a failing conversation

    def serve(self):
        server = self.server
        server.connections += 1
        selected = 0
        authed = server.password is None
        while True:
            try:
                argv = self.read_command()
            except ValueError as error:
                self.error(f"ERR {error}")
                return
            if not argv:
                return
            command = argv[0].decode().upper()
            server.commands.append(command)
            if command == "AUTH":
                secret = argv[-1]
                if server.password is not None and secret == server.password:
                    authed = True
                    self.status(b"OK")
                else:
                    self.error(b"WRONGPASS invalid password")
                continue
            if not authed:
                self.error(b"NOAUTH Authentication required.")
                continue
            if command == "SELECT":
                selected = int(argv[1])
                self.status(b"OK")
            elif command == "SET":
                server.databases.setdefault(selected, {})[argv[1]] = argv[2]
                self.status(b"OK")
            elif command == "GET":
                value = server.databases.get(selected, {}).get(argv[1])
                if value is None:
                    self.reply(b"$-1\r\n")
                else:
                    self.reply(b"$%d\r\n%s\r\n" % (len(value), value))
            elif command == "DEL":
                value = server.databases.setdefault(selected, {}).pop(
                    argv[1], None)
                self.reply(b":%d\r\n" % (1 if value is not None else 0))
            elif command == "PING":
                self.status(b"PONG")
            else:
                self.error(b"ERR unknown command")


class FakeRedis(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, password=None):
        super().__init__(("127.0.0.1", 0), FakeRedisHandler)
        self.password = password.encode() if password is not None else None
        self.databases = {0: {}}
        self.commands = []
        self.connections = 0
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self):
        return self.server_address[1]


def run_harness(harness, host, port, user, password, db, command, key):
    result = subprocess.run(
        [str(harness), host, str(port), user or "", password or "",
         str(db), command, key],
        check=False, capture_output=True, text=True)
    detail = (result.stdout + result.stderr).strip()
    return result.returncode == 0, detail


def offline(harness):
    """Run the harness against a scripted server.  No credentials needed."""
    failures = 0
    secret = "s3cret"
    key = digest_key(b"rswap-offline")

    server = FakeRedis(password=secret)
    try:
        cases = [
            ("store one page", "default", secret, 0, "put", key, True),
            ("load it back", "default", secret, 0, "get", key, True),
            ("missing key is ENOENT", "default", secret, 0, "get-missing",
             "00" * 48, True),
            ("wrong password is EACCES", "default", "nope", 0, "put-noauth",
             key, True),
            ("AUTH is required", "", "", 0, "put-noauth", key, True),
        ]
        for label, user, password, db, command, target, expected in cases:
            ok, detail = run_harness(harness, "127.0.0.1", server.port, user,
                                     password, db, command, target)
            if ok != expected:
                print(f"FAIL: {label}: {detail}")
                failures += 1
            else:
                print(f"PASS: {label}")

        stored = server.databases.get(0, {}).get(key.encode())
        if stored != page_bytes(key):
            print("FAIL: stored value is not the page image under the key")
            failures += 1
        else:
            print("PASS: stored value is the page image under the key")
        if set(server.databases.get(0, {})) != {key.encode()}:
            print("FAIL: backend created keys other than the user digest")
            failures += 1
        else:
            print("PASS: no key but the user digest was created")

        # A non-zero database must be selected, not written to db 0.
        ok, detail = run_harness(harness, "127.0.0.1", server.port, "",
                                 secret, 3, "put", key)
        if not ok or key.encode() not in server.databases.get(3, {}):
            print(f"FAIL: SELECT 3 not honored: {detail}")
            failures += 1
        else:
            print("PASS: SELECT 3 honored")

        # A value that is not exactly one page must not be returned.
        server.databases[0][key.encode()] = b"short"
        ok, detail = run_harness(harness, "127.0.0.1", server.port, "",
                                 secret, 0, "get-badlen", key)
        if not ok:
            print(f"FAIL: short object accepted: {detail}")
            failures += 1
        else:
            print("PASS: short object rejected")

        for required in ("AUTH", "SELECT"):
            if required not in server.commands:
                print(f"FAIL: backend never sent {required}")
                failures += 1

        # Eight pages must be pipelined over a single connection.
        for command in ("putbatch", "getbatch"):
            server.connections = 0
            server.commands.clear()
            ok, detail = run_harness(harness, "127.0.0.1", server.port,
                                     "default", secret, 0, command, key)
            want = "SET" if command == "putbatch" else "GET"
            sent = server.commands.count(want)
            if not ok:
                print(f"FAIL: {command}: {detail}")
                failures += 1
            if server.connections != 1:
                print(f"FAIL: {command} used {server.connections} "
                      f"connection(s), expected 1")
                failures += 1
            if sent != 32:
                print(f"FAIL: {command} sent {sent} {want}(s), expected 32")
                failures += 1
            elif not failures:
                print(f"PASS: {command} pipelined 32 {want}s over one "
                      f"connection")
        for i in range(32):
            page_key = f"{key[:94]}{i >> 4:x}{i & 15:x}".encode()
            if server.databases[0].get(page_key) != page_bytes(page_key.decode()):
                print(f"FAIL: batched page {i} missing or wrong")
                failures += 1
                break

        # The pool must move 64 pages over one connection.
        server.connections = 0
        server.commands.clear()
        ok, detail = run_harness(harness, "127.0.0.1", server.port, "default",
                                 secret, 0, "pooltest", key)
        sets = server.commands.count("SET")
        gets = server.commands.count("GET")
        if not ok:
            print(f"FAIL: pooltest: {detail}")
            failures += 1
        if server.connections != 1:
            print(f"FAIL: 8 batches used {server.connections} connection(s),"
                  f" expected 1 (pooled)")
            failures += 1
        if sets != 32 or gets != 32:
            print(f"FAIL: pooltest sent {sets} SET and {gets} GET,"
                  f" expected 32/32")
            failures += 1
        elif not failures:
            print("PASS: pooled connection carried 8 batches")
        if not failures:
            print("PASS: RESP client stores and loads pages by user digest")
    finally:
        server.shutdown()
        server.server_close()
    return failures


class RespClient:
    """Tiny RESP2 client, used to audit a server out of band."""

    def __init__(self, host, port, timeout=5):
        self.sock = socket.create_connection((host, port), timeout)
        self.stream = self.sock.makefile("rb")

    def close(self):
        self.stream.close()
        self.sock.close()

    def command(self, *args):
        out = b"*%d\r\n" % len(args)
        for arg in args:
            arg = arg if isinstance(arg, bytes) else str(arg).encode()
            out += b"$%d\r\n%s\r\n" % (len(arg), arg)
        self.sock.sendall(out)
        return self._reply()

    def _reply(self):
        line = self.stream.readline()
        if not line:
            raise RuntimeError("connection closed")
        kind, rest = line[:1], line[1:-2]
        if kind == b"+":
            return rest
        if kind == b"-":
            raise RuntimeError(rest.decode())
        if kind == b":":
            return int(rest)
        if kind == b"$":
            length = int(rest)
            return None if length < 0 else self.stream.read(length + 2)[:-2]
        raise RuntimeError(f"unsupported reply {line!r}")


def live(harness, args):
    """Run the harness against a real server and audit the stored objects."""
    failures = 0
    keys = [digest_key(os.urandom(48)) for _ in range(2)]

    client = RespClient(args.host, args.port)
    if args.password:
        client.command("AUTH", args.user or "default", args.password)
    if args.db:
        client.command("SELECT", args.db)
    try:
        before = client.command("DBSIZE")
        for key in keys:
            ok, detail = run_harness(harness, args.host, args.port, args.user,
                                     args.password, args.db, "put", key)
            if not ok:
                print(f"FAIL: live store: {detail}")
                failures += 1
                continue
            ok, detail = run_harness(harness, args.host, args.port, args.user,
                                     args.password, args.db, "get", key)
            if not ok:
                print(f"FAIL: live load: {detail}")
                failures += 1
            value = client.command("GET", key)
            if value != page_bytes(key):
                print("FAIL: Redis object differs from the page image")
                failures += 1
        ok, detail = run_harness(harness, args.host, args.port, args.user,
                                 args.password, args.db, "get-missing",
                                 digest_key(os.urandom(48)))
        if not ok:
            print(f"FAIL: live missing key: {detail}")
            failures += 1
        for key in keys:
            client.command("DEL", key)
        if client.command("DBSIZE") != before:
            print("FAIL: live run left objects behind")
            failures += 1
        if not failures:
            print(f"PASS: live Redis {args.host}:{args.port} stores each page "
                  f"under its user digest")
    finally:
        client.close()
    return failures


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true",
                        help="also test a real Redis server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6379)
    parser.add_argument("--user", default="default")
    parser.add_argument("--password",
                        default=os.environ.get("RSWAP_REDIS_PASSWORD", ""))
    parser.add_argument("--db", type=int, default=0)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[2]
    failures = check_shim_drift(root)
    with tempfile.TemporaryDirectory(prefix="rswap-redis-") as directory:
        harness = build_harness(root, directory)
        failures += offline(harness)
        if args.live:
            failures += live(harness, args)
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
