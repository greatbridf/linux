#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile actual backend and slot cleanup functions with deterministic shims.

The shims below stand in for the kernel interfaces the extracted code uses.
check_shim_drift() compares the shimmed constants and struct layouts against
mm/rswap.h, mm/rswap_backend.h and mm/rswap.c, so a change to the digest width,
the KV key length or the page/interface structs fails here instead of passing
silently against a stale shim.
"""

import argparse
import pathlib
import re
import subprocess
import tempfile


SHIMS = r"""
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#define PAGE_SIZE 4096
#define PAGE_SHIFT 12
#define GFP_NOIO 0
#define READ 0
#define WRITE 1
#define ITER_SOURCE 0
#define ITER_DEST 1
#define RSWAP_SHA256_HEXLEN 64
#define SHA256_DIGEST_SIZE 32
typedef uint8_t u8;
#define RSWAP_HASH_LEN 48
#define RSWAP_HASH_HEXLEN (2 * RSWAP_HASH_LEN)
#define RSWAP_KV_KEY_LEN 97
#define RSWAP_BATCH_MAX 32
#define RSWAP_HTTP_MAX_HEADER 2048
/*
 * The harness has no clock, so the deadline it passes to the code that takes
 * one is the far-future sentinel below: it never expires.
 */
#define RSWAP_SHIM_DEADLINE ((unsigned long)-1)
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define unlikely(x) (x)
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#define pr_debug_ratelimited(...) do { } while (0)
#define pr_err_ratelimited(...) do { } while (0)
#define pr_warn(...) do { } while (0)
typedef int64_t s64;
#define ktime_get_ns() ((s64)0)
#define kmalloc(size, flags) malloc(size)
#define kzalloc(size, flags) calloc(1, size)
#define kzalloc_obj(obj, flags) calloc(1, sizeof(obj))
#define kfree(ptr) free(ptr)
#define kvmalloc_array(count, size, flags) calloc((count), (size))
#define kvmalloc(size, flags) malloc(size)
#define kvfree(ptr) free(ptr)
#define __aligned(x) __attribute__((aligned(x)))
#define struct_size(ptr, member, count) (sizeof(*(ptr)) + (count))
#define PTR_ERR(ptr) ((long)(ptr))
#define IS_ERR(ptr) ((uintptr_t)(ptr) > (uintptr_t)-4096)
/*
 * The asynchronous swapin bookkeeping.  queue_work() runs the work item inline
 * in the submitting task, so the queued path is exercised end to end here.
 */
typedef struct { int v; } atomic_t;
#define atomic_read(p) ((p)->v)
#define atomic_set(p, value) ((p)->v = (value))
#define atomic_inc_return(p) (++(p)->v)
#define atomic_dec(p) (--(p)->v)
#define atomic_try_cmpxchg(p, old, new) \
    ({ int __cur = (p)->v; \
       bool __ok = __cur == *(old); \
       if (__ok) (p)->v = (new); else *(old) = __cur; __ok; })
#define atomic_sub(nr, p) ((p)->v -= (nr))
typedef struct { int64_t v; } atomic64_t;
#define atomic64_read(p) ((p)->v)
#define atomic64_set(p, value) ((p)->v = (value))
#define atomic64_add(value, p) ((p)->v += (value))
#define atomic64_inc(p) ((p)->v++)
typedef struct { int v; } refcount_t;
#define refcount_set(p, value) ((p)->v = (value))
#define refcount_inc(p) ((p)->v++)
#define refcount_dec(p) ((p)->v--)
#define refcount_dec_and_test(p) (--(p)->v == 0)
struct workqueue_struct { int unused; };
struct work_struct { void (*func)(struct work_struct *); };
#define WQ_MEM_RECLAIM 0
#define INIT_WORK(w, f) ((w)->func = (f))
static struct workqueue_struct wq_stub;
static bool queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
    work->func(work);
    return true;
}
static void flush_workqueue(struct workqueue_struct *wq) { }
static struct workqueue_struct *alloc_workqueue(const char *name,
                                                unsigned int flags,
                                                unsigned int max_active)
{
    return &wq_stub;
}
static void destroy_workqueue(struct workqueue_struct *wq) { }
#define cmpxchg(p, old, new) \
    ({ __typeof__(*(p)) __prev = *(p); \
       if (__prev == (old)) { \
           *(p) = (new); \
       } \
       __prev; })
typedef struct { unsigned long val; } swp_entry_t;
struct socket { int unused; };
struct iov_iter { int unused; };
struct kiocb { void (*ki_complete)(struct kiocb *, long); };
struct folio;
/* One base page image; @owner stands in for the compound-head lookup. */
struct page { unsigned char *data; struct folio *owner; };
struct folio {
    swp_entry_t swap;
    unsigned char *data;
    unsigned long nr_pages;
    struct page pages[RSWAP_BATCH_MAX * 2];
};
struct rswap_kv_page {
    const char *key;
    struct page *page;
};
struct bio_vec {
    struct folio *folio;
    struct page *bv_page;
    size_t bv_len, bv_offset;
};
struct rswap_stats { int unused; };
static struct rswap_stats rswap_total, rswap_write_io, rswap_read_io;
static struct rswap_stats device_stats;
static struct {
    unsigned int pages_written, pages_read, errors_written, errors_read;
    unsigned int no_digest, no_entry, batches;
    unsigned int dev_pages_written, dev_pages_read, dev_errors_read;
} counted;
struct swap_info_struct {
    unsigned long max;
    void *rswap_hashes;
    struct rswap_stats *rswap_stats;
    int type;
};
static struct swap_info_struct swap_info_stub = { .rswap_stats = &device_stats };
static void rswap_stats_io(struct rswap_stats *io, int64_t ns)
{
    counted.batches++;
}
static void rswap_stats_pages(struct rswap_stats *stats, int rw,
                              unsigned int pages)
{
    if (stats == &device_stats) {
        if (rw == WRITE)
            counted.dev_pages_written += pages;
        else
            counted.dev_pages_read += pages;
    } else if (stats == &rswap_total) {
        if (rw == WRITE)
            counted.pages_written += pages;
        else
            counted.pages_read += pages;
    }
}
static void rswap_stats_errors(struct rswap_stats *stats, int rw,
                               unsigned int pages)
{
    if (stats == &device_stats) {
        if (rw == READ)
            counted.dev_errors_read += pages;
    } else if (stats == &rswap_total) {
        if (rw == WRITE)
            counted.errors_written += pages;
        else
            counted.errors_read += pages;
    }
}
static void rswap_stats_key_failure(struct rswap_stats *stats, int rw, int err,
                                    unsigned int pages)
{
    if (rw == WRITE && err == -ENODATA)
        counted.no_digest++;
    else if (rw == READ && err == -ENOENT)
        counted.no_entry++;
    rswap_stats_errors(stats, rw, pages);
}
static struct rswap_stats *rswap_stats_get(struct rswap_stats *stats)
{
    return stats;
}
static void rswap_stats_put(struct rswap_stats *stats) { }
struct swap_iocb {
    struct kiocb iocb;
    unsigned int nr_bvecs;
    size_t len;
    struct bio_vec bvecs[4];
};
struct swap_io_ctx {
    struct swap_iocb *sio;
    struct swap_info_struct *sis;
};
static struct socket socket_stub;
static const char *response_data;
static size_t response_size, response_offset;
static int response_error;
static long completion;
static int requests;
static int moved;
/*
 * The fixture digests this harness uses as KV keys.  The real key is the hex
 * digest user space supplied for the page; the harness has no digest program,
 * so the test registers one fixture digest string per swap offset up front and
 * rswap_page_key() below looks it up.  No key is computed from the swap entry,
 * the page contents or anything else the kernel derived.
 */
#define SHIM_MAX_SLOTS 256
static char shim_keys[SHIM_MAX_SLOTS][RSWAP_KV_KEY_LEN];
static unsigned char stored[SHIM_MAX_SLOTS][PAGE_SIZE];
static size_t stored_len[SHIM_MAX_SLOTS];
static int active_key;
#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
static void complete(struct kiocb *iocb, long ret) { completion = ret; }
static void swap_fs_prepare_rw(struct swap_io_ctx *ctx, int rw,
                               struct iov_iter *iter)
{
    ctx->sio->iocb.ki_complete = complete;
}
static unsigned int memalloc_noio_save(void) { return 0; }
static void memalloc_noio_restore(unsigned int flags) { }
static struct folio *bvec_folio(struct bio_vec *bv) { return bv->folio; }
static unsigned long folio_page_idx(struct folio *folio, struct page *page)
{
    return page - folio->pages;
}
static unsigned long folio_nr_pages(struct folio *folio)
{
    return folio->nr_pages ? folio->nr_pages : 1;
}
/* Mergefability probes: the real ones read page_ext resp. the device table. */
static bool digest_ok = true;
static bool entry_ok = true;
static bool rswap_page_get_hash(struct page *page, unsigned char *hash)
{
    return digest_ok;
}
static bool rswap_hash_load(struct swap_info_struct *si, swp_entry_t entry,
                            unsigned char *hash)
{
    return entry_ok;
}
/* Point the base pages of @folio at @data and back at @folio. */
static void shim_bind_pages(struct folio *folio, unsigned long nr,
                            unsigned char *data)
{
    unsigned long i;

    folio->nr_pages = nr;
    for (i = 0; i < nr; i++) {
        folio->pages[i].data = data + i * PAGE_SIZE;
        folio->pages[i].owner = folio;
    }
}
static struct page *folio_page(struct folio *folio, unsigned long index)
{
    return &folio->pages[index];
}
static swp_entry_t folio_swap_entry(struct folio *folio, unsigned long index)
{
    return (swp_entry_t) { .val = folio->swap.val + index };
}
static struct folio *page_folio(struct page *page)
{
    return page->owner;
}
static swp_entry_t folio_page_swap_entry(struct folio *folio,
                                         struct page *page)
{
    return folio_swap_entry(folio, folio_page_idx(folio, page));
}
static void *kmap_local_page(struct page *page) { return page->data; }
static void kunmap_local(void *address) { }
static unsigned int swp_type(swp_entry_t entry) { return 0; }
static unsigned long swp_offset(swp_entry_t entry) { return entry.val; }
static struct swap_info_struct *__swap_entry_to_info(swp_entry_t entry)
{
    return &swap_info_stub;
}
static struct socket *rswap_connect(void) { return &socket_stub; }
static void kernel_sock_shutdown(struct socket *sock, int how) { }
static void sock_release(struct socket *sock) { }
static unsigned long rswap_sock_deadline(unsigned int timeout_ms)
{
    return RSWAP_SHIM_DEADLINE;
}
static bool rswap_sock_expired(unsigned long deadline)
{
    return deadline != RSWAP_SHIM_DEADLINE;
}
/*
 * Stand-in for the real key source: hand back the fixture digest registered for
 * this swap offset, or fail the way the real one does when none is attached.
 */
static int shim_key_index(const char *key)
{
    unsigned long i;

    for (i = 0; i < SHIM_MAX_SLOTS; i++)
        if (shim_keys[i][0] && !strcmp(shim_keys[i], key))
            return (int)i;
    return -1;
}

static void shim_register_keys(void)
{
    unsigned long offset;

    for (offset = 0; offset < SHIM_MAX_SLOTS; offset++)
        snprintf(shim_keys[offset], sizeof(shim_keys[0]), "%096lx",
                 0x1000000000000000UL + offset * 0x9e3779b97f4a7c15UL);
}

static int rswap_page_key(struct swap_info_struct *si, struct page *page,
                          swp_entry_t entry, int rw, char *hex)
{
    unsigned long offset = swp_offset(entry);

    if (offset >= SHIM_MAX_SLOTS || !shim_keys[offset][0])
        return rw == WRITE ? -ENODATA : -ENOENT;
    snprintf(hex, RSWAP_KV_KEY_LEN, "%s", shim_keys[offset]);
    return 0;
}
static char *skip_spaces(const char *p)
{
    while (isspace((unsigned char)*p))
        p++;
    return (char *)p;
}
static int kstrtoul(const char *text, unsigned int base, unsigned long *out)
{
    char *end;
    if (*text == '-')
        return -EINVAL;
    errno = 0;
    *out = strtoul(text, &end, base);
    return errno || end == text || *end ? -EINVAL : 0;
}
static int rswap_sock_recv(struct socket *sock, char *buf, int len)
{
    size_t available = response_size - response_offset;
    size_t count = min_t(size_t, available, len);
    count = min_t(size_t, count, 37);
    if (!count)
        return response_error;
    memcpy(buf, response_data + response_offset, count);
    response_offset += count;
    return count;
}
/* The body goes straight into the page image the core handed over. */
static int rswap_sock_recv_page(struct socket *sock, struct page *page,
                                size_t off, size_t len,
                                unsigned long deadline)
{
    size_t done = 0;
    int ret;

    if (rswap_sock_expired(deadline))
        return -ETIMEDOUT;
    while (done < len) {
        ret = rswap_sock_recv(sock, (char *)page->data + off + done,
                              len - done);
        if (ret <= 0)
            return ret ? ret : -EIO;
        done += ret;
    }
    return 0;
}
static void set_response(const char *data, size_t len, int error)
{
    response_data = data;
    response_size = len;
    response_offset = 0;
    response_error = error;
}
static int rswap_kv_store(struct rswap_kv_page *pages, unsigned int nr,
                          size_t len)
{
    unsigned int i;

    requests++;
    for (i = 0; i < nr; i++) {
        active_key = shim_key_index(pages[i].key);
        assert(active_key >= 0 && len <= sizeof(stored[0]));
        memcpy(stored[active_key], pages[i].page->data, len);
        stored_len[active_key] = len;
        moved++;
    }
    return 0;
}
static int rswap_kv_load(struct rswap_kv_page *pages, unsigned int nr,
                         size_t len)
{
    unsigned int i;

    requests++;
    for (i = 0; i < nr; i++) {
        active_key = shim_key_index(pages[i].key);
        assert(active_key >= 0);
        if (stored_len[active_key] != len)
            return -ENOENT;
        memcpy(pages[i].page->data, stored[active_key], len);
        moved++;
    }
    return 0;
}
"""

PARSER_MAIN = r"""
int main(void)
{
    const char full[] =
        "HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nABCD";
    const char short_body[] =
        "HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nAB";
    const char wrong_length[] =
        "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nAB";
    const char duplicate[] =
        "HTTP/1.0 200 OK\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nABCD";
    const char missing[] = "HTTP/1.0 200 OK\r\n\r\nABCD";
    const char not_found[] = "HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    const char write_ok[] = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    char data[4];
    struct page page = { .data = (unsigned char *)data };
    int failures = 0;
    set_response(full, sizeof(full) - 1, 0);
    assert(rswap_parse_response(&socket_stub, &page, 4, true,
                                RSWAP_SHIM_DEADLINE) == 0);
    assert(!memcmp(data, "ABCD", 4));
    set_response(write_ok, sizeof(write_ok) - 1, 0);
    assert(rswap_parse_response(&socket_stub, NULL, 4, false,
                                RSWAP_SHIM_DEADLINE) == 0);
    set_response(short_body, sizeof(short_body) - 1, 0);
    if (rswap_parse_response(&socket_stub, &page, 4, true,
                             RSWAP_SHIM_DEADLINE) == 0) {
        puts("FAIL: premature EOF reported as a complete read");
        failures++;
    }
    set_response(wrong_length, sizeof(wrong_length) - 1, 0);
    if (rswap_parse_response(&socket_stub, &page, 4, true,
                             RSWAP_SHIM_DEADLINE) == 0) {
        puts("FAIL: wrong Content-Length accepted");
        failures++;
    }
    set_response(missing, sizeof(missing) - 1, 0);
    if (rswap_parse_response(&socket_stub, &page, 4, true,
                             RSWAP_SHIM_DEADLINE) == 0) {
        puts("FAIL: missing Content-Length accepted");
        failures++;
    }
    set_response(duplicate, sizeof(duplicate) - 1, 0);
    if (rswap_parse_response(&socket_stub, &page, 4, true,
                             RSWAP_SHIM_DEADLINE) == 0) {
        puts("FAIL: duplicate Content-Length accepted");
        failures++;
    }
    set_response(not_found, sizeof(not_found) - 1, 0);
    assert(rswap_parse_response(&socket_stub, &page, 4, true,
                                RSWAP_SHIM_DEADLINE) < 0);
    set_response(short_body, sizeof(short_body) - 1, -EAGAIN);
    if (rswap_parse_response(&socket_stub, &page, 4, true,
                             RSWAP_SHIM_DEADLINE) != -EAGAIN) {
        puts("FAIL: socket timeout errno lost");
        failures++;
    }
    if (!failures)
        puts("PASS: actual response parser rejects incomplete data");
    return !!failures;
}
"""

BACKEND_MAIN = r"""
int main(void)
{
    unsigned char original[PAGE_SIZE * 8], actual[PAGE_SIZE * 8];
    struct folio big = { .swap = { .val = 1 }, .data = original };
    struct swap_iocb sio = { .nr_bvecs = 1, .len = sizeof(original) };
    struct swap_io_ctx ctx = { .sio = &sio, .sis = &swap_info_stub };
    size_t i;
    for (i = 0; i < sizeof(original); i++)
        original[i] = (i * 73 + i / PAGE_SIZE * 29) & 255;
    shim_bind_pages(&big, 8, original);
    sio.bvecs[0] = (struct bio_vec) {
        .folio = &big, .bv_page = &big.pages[0], .bv_len = sizeof(original),
    };
    /*
     * Only the workqueue itself is missing here: queue_work() runs the work
     * item inline, so every read below goes through the queued path and
     * completes from rswap_read_batch_work().
     */
    shim_register_keys();
    assert(rswap_read_wq_init() == 0);
    rswap_submit_write(&ctx);
    assert(completion == sizeof(original));
    /* RSWAP_BATCH_MAX == 8: the whole 8 page folio is one backend call. */
    if (requests != 1 || moved != 8) {
        printf("FAIL: 8 page folio stored in %d call(s) moving %d page(s),"
               " expected 1/8\n", requests, moved);
        return 1;
    }
    if (counted.pages_written != 8 || counted.dev_pages_written != 8 ||
        counted.batches != 1) {
        printf("FAIL: counters saw %u total / %u device page(s) in %u"
               " batch(es), expected 8/8/1\n", counted.pages_written,
               counted.dev_pages_written, counted.batches);
        return 1;
    }
    /* Read the original large folio back as eight independent base pages. */
    for (i = 0; i < 8; i++) {
        struct folio small = {
            .swap = { .val = 1 + i }, .data = actual + i * PAGE_SIZE,
        };
        shim_bind_pages(&small, 1, small.data);
        sio.nr_bvecs = 1;
        sio.len = PAGE_SIZE;
        sio.bvecs[0] = (struct bio_vec) {
            .folio = &small, .bv_page = &small.pages[0], .bv_len = PAGE_SIZE,
        };
        rswap_submit_read(&ctx);
        assert(completion == PAGE_SIZE);
    }
    assert(!memcmp(original, actual, sizeof(original)));
    if (requests != 9 || moved != 16) {
        printf("FAIL: 8 single page reads took %d call(s) moving %d page(s),"
               " expected 9/16\n", requests, moved);
        return 1;
    }
    if (counted.pages_read != 8 || counted.dev_pages_read != 8 ||
        counted.batches != 9) {
        printf("FAIL: counters saw %u total / %u device read page(s) in %u"
               " batch(es), expected 8/8/9\n", counted.pages_read,
               counted.dev_pages_read, counted.batches);
        return 1;
    }
    /* More pages than one batch must be split into full and tail batches. */
    {
        unsigned char many[PAGE_SIZE * 12], wide_actual[PAGE_SIZE * 12];
        /* High entries so the round trip does not disturb the slots above. */
        struct folio wide = { .swap = { .val = 20 }, .data = many };
        struct folio back = { .swap = { .val = 20 }, .data = wide_actual };
        struct swap_iocb wide_sio = { .nr_bvecs = 1, .len = sizeof(many) };
        struct swap_io_ctx wide_ctx = { .sio = &wide_sio,
                                        .sis = &swap_info_stub };

        for (i = 0; i < sizeof(many); i++)
            many[i] = (i * 31 + i / PAGE_SIZE * 17) & 255;
        shim_bind_pages(&wide, 12, many);
        shim_bind_pages(&back, 12, wide_actual);
        wide_sio.bvecs[0] = (struct bio_vec) {
            .folio = &wide, .bv_page = &wide.pages[0],
            .bv_len = sizeof(many),
        };
        memset(wide_actual, 0, sizeof(many));
        requests = moved = 0;
        rswap_submit_write(&wide_ctx);
        assert(completion == sizeof(many));
        /* RSWAP_BATCH_MAX == 32: 12 pages still fit in one batch. */
        if (requests != 1 || moved != 12) {
            printf("FAIL: 12 page folio stored in %d call(s) moving %d page(s),"
                   " expected 1/12\n", requests, moved);
            return 1;
        }
        wide_sio.bvecs[0] = (struct bio_vec) {
            .folio = &back, .bv_page = &back.pages[0],
            .bv_len = sizeof(many),
        };
        requests = moved = 0;
        rswap_submit_read(&wide_ctx);
        assert(completion == sizeof(many));
        if (requests != 1 || moved != 12) {
            printf("FAIL: 12 page folio read in %d call(s) moving %d page(s),"
                   " expected 1/12\n", requests, moved);
            return 1;
        }
        if (memcmp(many, wide_actual, sizeof(many))) {
            puts("FAIL: batched multi-folio round trip corrupted data");
            return 1;
        }
    }
    /* More pages than one batch must be split into full and tail batches. */
    {
        enum { PAGES = RSWAP_BATCH_MAX + 8 };
        static unsigned char many[PAGE_SIZE * PAGES];
        static unsigned char many_actual[PAGE_SIZE * PAGES];
        struct folio wide = { .swap = { .val = 100 }, .data = many };
        struct folio back = { .swap = { .val = 100 }, .data = many_actual };
        struct swap_iocb wide_sio = { .nr_bvecs = 1, .len = sizeof(many) };
        struct swap_io_ctx wide_ctx = { .sio = &wide_sio,
                                        .sis = &swap_info_stub };

        for (i = 0; i < sizeof(many); i++)
            many[i] = (i * 13 + i / PAGE_SIZE * 61) & 255;
        shim_bind_pages(&wide, PAGES, many);
        shim_bind_pages(&back, PAGES, many_actual);
        wide_sio.bvecs[0] = (struct bio_vec) {
            .folio = &wide, .bv_page = &wide.pages[0],
            .bv_len = sizeof(many),
        };
        requests = moved = 0;
        rswap_submit_write(&wide_ctx);
        assert(completion == sizeof(many));
        if (requests != 2 || moved != PAGES) {
            printf("FAIL: %d page folio stored in %d call(s) moving %d page(s),"
                   " expected 2/%d\n", (int)PAGES, requests, moved, (int)PAGES);
            return 1;
        }
        memset(many_actual, 0, sizeof(many_actual));
        wide_sio.bvecs[0] = (struct bio_vec) {
            .folio = &back, .bv_page = &back.pages[0],
            .bv_len = sizeof(many),
        };
        requests = moved = 0;
        rswap_submit_read(&wide_ctx);
        assert(completion == sizeof(many));
        if (requests != 2 || moved != PAGES) {
            printf("FAIL: %d page folio read in %d call(s) moving %d page(s),"
                   " expected 2/%d\n", (int)PAGES, requests, moved, (int)PAGES);
            return 1;
        }
        if (memcmp(many, many_actual, sizeof(many))) {
            puts("FAIL: split batch round trip corrupted data");
            return 1;
        }
    }
    /* Read multiple folios in one request, with callback initialized first. */
    struct folio first = { .swap = { .val = 1 }, .data = actual };
    struct folio second = { .swap = { .val = 2 }, .data = actual + PAGE_SIZE };
    shim_bind_pages(&first, 1, first.data);
    shim_bind_pages(&second, 1, second.data);
    sio.nr_bvecs = 2;
    sio.len = PAGE_SIZE * 2;
    sio.bvecs[0] = (struct bio_vec) {
        .folio = &first, .bv_page = &first.pages[0], .bv_len = PAGE_SIZE,
    };
    sio.bvecs[1] = (struct bio_vec) {
        .folio = &second, .bv_page = &second.pages[0], .bv_len = PAGE_SIZE,
    };
    sio.iocb.ki_complete = NULL;
    memset(actual, 0, PAGE_SIZE * 2);
    requests = moved = 0;
    rswap_submit_read(&ctx);
    assert(completion == PAGE_SIZE * 2);
    assert(!memcmp(original, actual, PAGE_SIZE * 2));
    if (requests != 1 || moved != 2) {
        printf("FAIL: two folios read in %d call(s) moving %d page(s),"
               " expected 1/2\n", requests, moved);
        return 1;
    }
    /* Merging is only allowed when every page of the folio is movable. */
    {
        struct folio candidate = { .swap = { .val = 1 }, .nr_pages = 8 };
        struct folio previous = { .swap = { .val = 1 } };

        if (!rswap_can_merge(&candidate, &previous, PAGE_SIZE, WRITE) ||
            !rswap_can_merge(&candidate, &previous, PAGE_SIZE, READ)) {
            puts("FAIL: ready folio refused a merged request");
            return 1;
        }
        /*
         * A page without a digest cannot be moved: writeout reads the slot and
         * falls back to the page_ext digest when the slot holds none, swapin
         * only ever reads the slot.  Neither source may be ignored.
         */
        entry_ok = false;
        if (!rswap_can_merge(&candidate, &previous, PAGE_SIZE, WRITE)) {
            puts("FAIL: page_ext digest no longer kept a write mergeable");
            return 1;
        }
        if (rswap_can_merge(&candidate, &previous, PAGE_SIZE, READ)) {
            puts("FAIL: merged a read whose entries have no digest");
            return 1;
        }
        digest_ok = false;
        if (rswap_can_merge(&candidate, &previous, PAGE_SIZE, WRITE)) {
            puts("FAIL: merged a write whose pages have no digest");
            return 1;
        }
        entry_ok = true;
        digest_ok = false;
        if (!rswap_can_merge(&candidate, &previous, PAGE_SIZE, WRITE) ||
            !rswap_can_merge(&candidate, &previous, PAGE_SIZE, READ)) {
            puts("FAIL: write-only digest gate blocked a merge");
            return 1;
        }
        digest_ok = true;
    }
    /* A missing page must fail completion and remain not uptodate. */
    stored_len[2] = 0;
    rswap_submit_read(&ctx);
    assert(completion < 0);
    if (counted.errors_read != 2 || counted.dev_errors_read != 2) {
        printf("FAIL: failed two page batch counted %u total / %u device"
               " error(s), expected 2/2\n", counted.errors_read,
               counted.dev_errors_read);
        return 1;
    }
    /* Every request completed once and released its queue slot. */
    if (atomic_read(&rswap_read_inflight) ||
        atomic64_read(&rswap_read_fallbacks) ||
        !atomic64_read(&rswap_read_submits)) {
        puts("FAIL: reads bypassed or leaked the asynchronous path");
        return 1;
    }
    /* Without a workqueue the same request completes in the submitting task. */
    stored_len[2] = PAGE_SIZE;
    rswap_read_wq = NULL;
    memset(actual, 0, PAGE_SIZE * 2);
    requests = moved = 0;
    rswap_submit_read(&ctx);
    assert(completion == PAGE_SIZE * 2);
    assert(!memcmp(original, actual, PAGE_SIZE * 2));
    if (atomic64_read(&rswap_read_fallbacks) != 1 ||
        atomic_read(&rswap_read_inflight)) {
        puts("FAIL: swapin without a workqueue did not fall back inline");
        return 1;
    }
    puts("PASS: actual submit paths batch pages and preserve addressing/errors");
    return 0;
}
"""

STATS_SHIMS = r"""
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int64_t s64;
typedef struct { s64 v; } atomic64_t;
#define atomic64_read(p) ((p)->v)
#define atomic64_add(value, p) ((p)->v += (value))
#define atomic64_inc(p) ((p)->v++)
#define atomic64_cmpxchg(p, old, new)					\
	({ s64 __old = (p)->v; if (__old == (old)) (p)->v = (new); __old; })
typedef struct { int v; } refcount_t;
#define refcount_inc(p) ((p)->v++)
#define refcount_dec_and_test(p) (--(p)->v == 0)
#define kfree(ptr) free(ptr)
#define WRITE 1
#define READ 0
"""

STATS_MAIN = r"""
int main(void)
{
    struct rswap_stats stats = { };
    int failures = 0;

    rswap_stats_pages(&stats, WRITE, 3);
    rswap_stats_pages(&stats, READ, 2);
    rswap_stats_errors(&stats, WRITE, 1);
    assert(atomic64_read(&stats.pages_written) == 3);
    assert(atomic64_read(&stats.pages_read) == 2);
    assert(atomic64_read(&stats.errors_written) == 1);

    /*
     * Only the documented failures count as no digest / no entry, and every
     * page that stayed where it was is a failed page.
     */
    rswap_stats_key_failure(&stats, WRITE, -ENODATA, 4);
    rswap_stats_key_failure(&stats, READ, -ENOENT, 2);
    rswap_stats_key_failure(&stats, READ, -EIO, 3);
    if (atomic64_read(&stats.no_digest) != 1 ||
        atomic64_read(&stats.no_entry) != 1 ||
        atomic64_read(&stats.errors_written) != 5 ||
        atomic64_read(&stats.errors_read) != 5) {
        puts("FAIL: key failures miscounted");
        failures++;
    }

    /* A device without counters (or no pages) must be tolerated. */
    rswap_stats_pages(NULL, WRITE, 4);
    rswap_stats_pages(&stats, WRITE, 0);
    rswap_stats_errors(NULL, READ, 4);
    rswap_stats_key_failure(NULL, WRITE, -ENODATA, 4);
    assert(atomic64_read(&stats.pages_written) == 3);

    /* Timing: batch count, accumulated and peak time. */
    rswap_stats_io(&rswap_write_io, 100);
    rswap_stats_io(&rswap_write_io, 40);
    rswap_stats_io(&rswap_write_io, 250);
    if (atomic64_read(&rswap_write_io.batches) != 3 ||
        atomic64_read(&rswap_write_io.ns) != 390 ||
        atomic64_read(&rswap_write_io.max_ns) != 250) {
        puts("FAIL: batch timing counters are wrong");
        failures++;
    }
    assert(atomic64_read(&rswap_read_io.batches) == 0);

    if (!failures)
        puts("PASS: actual counters account pages, failures and peak time");
    return !!failures;
}
"""

HASH_SHIMS = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SHA256_DIGEST_SIZE 32
#define RSWAP_SHA256_HEXLEN 64
#define RSWAP_HASH_LEN 48
#define RSWAP_HASH_HEXLEN (2 * RSWAP_HASH_LEN)
#define RSWAP_KV_KEY_LEN 97
#define WRITE 1
#define SWAPFILE_CLUSTER 4
#define GFP_NOWAIT 0
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#define smp_store_release(ptr, value) \
    __atomic_store_n((ptr), (value), __ATOMIC_RELEASE)
#define smp_load_acquire(ptr) __atomic_load_n((ptr), __ATOMIC_ACQUIRE)
#define READ_ONCE(x) (x)
#define cmpxchg(ptr, old, new) __sync_val_compare_and_swap((ptr), (old), (new))
#define cmpxchg_release(ptr, old, new) cmpxchg((ptr), (old), (new))
#define kzalloc_obj(obj, gfp) calloc(1, sizeof(obj))
#define kfree(ptr) free(ptr)
typedef struct { unsigned long val; } swp_entry_t;
typedef uint8_t u8;
typedef unsigned int gfp_t;
struct page { int unused; };
struct rswap_hash {
    uint8_t data[RSWAP_HASH_LEN];
    uint8_t valid;
};
struct rswap_hash_table {
    struct rswap_hash *hashes[SWAPFILE_CLUSTER];
};
struct swap_cluster_info {
    struct rswap_hash_table *hash_table;
};
struct swap_info_struct {
    unsigned long max;
    struct swap_cluster_info *cluster_info;
};
static struct swap_cluster_info *__swap_offset_to_cluster(
        struct swap_info_struct *si, unsigned long offset)
{
    return &si->cluster_info[offset / SWAPFILE_CLUSTER];
}
/*
 * The legacy /proc/sys/vm/rswap/attach digest is a 32-byte SHA-256;
 * rswap_page_key() zero extends it to the slot width.
 */
static bool page_hash_available;
static uint8_t attached_hash[SHA256_DIGEST_SIZE];
static unsigned long swp_offset(swp_entry_t entry) { return entry.val; }
static bool rswap_page_get_hash(struct page *page, u8 *hash)
{
    if (!page_hash_available)
        return false;
    memcpy(hash, attached_hash, sizeof(attached_hash));
    return true;
}
static void bin2hex(char *dst, const u8 *src, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++)
        sprintf(dst + i * 2, "%02x", src[i]);
}
"""

HASH_MAIN = r"""
int main(void)
{
    struct swap_cluster_info clusters[2] = { };
    struct swap_info_struct si = { .max = 2 * SWAPFILE_CLUSTER,
                                   .cluster_info = clusters };
    uint8_t first[RSWAP_HASH_LEN], second[RSWAP_HASH_LEN];
    uint8_t actual[RSWAP_HASH_LEN];
    char expected_hex[RSWAP_KV_KEY_LEN], hex[RSWAP_KV_KEY_LEN];
    struct rswap_hash *slot, *reserved;
    struct page page = { };
    swp_entry_t entry = { .val = SWAPFILE_CLUSTER + 1 };
    size_t i;

    for (i = 0; i < sizeof(first); i++) {
        first[i] = i;
        second[i] = 255 - i;
    }

    /* The digest resolved at unmap time is what writeout uses. */
    assert(rswap_hash_store(&si, entry, first) == 0);
    assert(rswap_hash_load(&si, entry, actual));
    assert(!memcmp(actual, first, sizeof(actual)));
    assert(rswap_page_key(&si, &page, entry, WRITE, expected_hex) == 0);
    assert(rswap_page_key(&si, &page, entry, 0, hex) == 0);
    assert(!strcmp(hex, expected_hex));
    assert(strlen(expected_hex) == RSWAP_HASH_HEXLEN);

    /*
     * A slot reserved when the folio entered the swap cache, but never
     * filled in, has no digest: writeout has to fail with -ENODATA instead of
     * emitting the all-zero key.  This is the reservation rswap_prepare_hashes()
     * makes; only the 'valid' flag tells it apart from a filled slot.
     */
    entry.val = SWAPFILE_CLUSTER + 2;
    reserved = rswap_slot_get(&si, entry.val, GFP_NOWAIT);
    assert(reserved && !reserved->valid);
    page_hash_available = false;
    memset(hex, 'x', sizeof(hex) - 1);
    hex[sizeof(hex) - 1] = '\0';
    assert(!rswap_hash_load(&si, entry, actual));
    assert(rswap_page_key(&si, &page, entry, WRITE, hex) == -ENODATA);
    assert(hex[0] == 'x');

    /* A slot in another cluster is independent of it. */
    entry.val = 1;
    assert(!rswap_hash_load(&si, entry, actual));
    assert(rswap_hash_store(&si, entry, second) == 0);
    assert(rswap_hash_load(&si, entry, actual));
    assert(!memcmp(actual, second, sizeof(actual)));

    /*
     * Releasing the swap entry runs the real rswap_hash_invalidate(): the
     * digest is gone, but the slot object stays with its cluster for the rest of
     * the cluster's life, so the lock-free lookup cannot dereference freed
     * memory.
     */
    slot = rswap_slot_lookup(&si, entry.val);
    assert(slot);
    rswap_hash_invalidate(&si, entry.val, 1);
    assert(!rswap_hash_load(&si, entry, actual));
    assert(!slot->valid);
    assert(rswap_slot_lookup(&si, entry.val) == slot);
    assert(clusters[0].hash_table->hashes[1] == slot);

    /* The slot is reusable: the next digest becomes the key. */
    entry.val = 1;
    assert(rswap_hash_store(&si, entry, first) == 0);
    assert(rswap_hash_load(&si, entry, actual));
    assert(!memcmp(actual, first, sizeof(actual)));
    assert(rswap_page_key(&si, &page, entry, WRITE, expected_hex) == 0);
    bin2hex(hex, first, RSWAP_HASH_LEN);
    hex[RSWAP_HASH_HEXLEN] = '\0';
    assert(!strcmp(hex, expected_hex));
    bin2hex(hex, second, RSWAP_HASH_LEN);
    hex[RSWAP_HASH_HEXLEN] = '\0';
    assert(strcmp(hex, expected_hex));

    /* Missing user digests fail writeout, and swapin has no fallback. */
    page_hash_available = false;
    entry.val = SWAPFILE_CLUSTER + 3;
    assert(rswap_page_key(&si, &page, entry, 0, hex) == -ENOENT);
    assert(rswap_page_key(&si, &page, entry, WRITE, hex) == -ENODATA);

    /* Offsets beyond the device are rejected, never indexed. */
    entry.val = si.max;
    assert(rswap_hash_store(&si, entry, first) == -ENOMEM);
    assert(!rswap_hash_load(&si, entry, actual));

    /* A page_ext digest still reaches the table on writeout. */
    page_hash_available = true;
    memcpy(attached_hash, first, sizeof(attached_hash));
    entry.val = 0;
    assert(rswap_page_key(&si, &page, entry, WRITE, expected_hex) == 0);
    assert(rswap_hash_load(&si, entry, actual));
    assert(!memcmp(actual, first, sizeof(attached_hash)));
    for (i = sizeof(attached_hash); i < sizeof(actual); i++)
        assert(!actual[i]);

    puts("PASS: actual per-entry key path stores and reloads writeout digests");
    return 0;
}
"""

FREE_SHIMS = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#define SWP_BLKDEV (1 << 6)
#define SWP_XSWAP (1 << 14)
#define SWP_RSWAP (1 << 15)
struct block_device;
struct block_device_operations {
    void (*swap_slot_free_notify)(struct block_device *, unsigned long);
};
struct gendisk { const struct block_device_operations *fops; };
struct block_device { struct gendisk *bd_disk; };
struct swap_info_struct {
    unsigned int flags;
    int type;
    struct block_device *bdev;
};
static long nr_swap_pages;
static unsigned long first_offset;
static unsigned int count, arch_calls, notify_calls, zswap_calls;
static unsigned int hash_invalidations;
static bool remote, barrier_done;
static void zswap_invalidate(int type, unsigned long offset, unsigned long nr)
{
    assert(type == 3 && offset == first_offset && nr == count);
    assert(!arch_calls && !barrier_done);
    zswap_calls++;
}
static void arch_swap_invalidate_page(int type, unsigned long offset)
{
    assert(type == 3 && offset == first_offset + arch_calls);
    assert(!barrier_done);
    arch_calls++;
}
static void notify(struct block_device *bdev, unsigned long offset)
{
    assert(bdev && offset == first_offset + notify_calls);
    assert(arch_calls == notify_calls + 1 && !barrier_done);
    notify_calls++;
}
static void smp_wmb(void)
{
    assert(arch_calls == count);
    barrier_done = true;
}
static void atomic_long_add(unsigned int nr, long *value)
{
    assert(barrier_done && nr == count);
    *value += nr;
}
static void swap_usage_sub(struct swap_info_struct *si, unsigned int nr)
{
    assert(si->type == 3 && nr == count);
    assert(barrier_done && nr_swap_pages == count);
}
static void rswap_hash_invalidate(struct swap_info_struct *si,
                                  unsigned long offset, unsigned int nr)
{
    assert((si->flags & SWP_RSWAP) && offset == first_offset && nr == count);
    hash_invalidations++;
}
"""

FREE_MAIN = r"""
int main(void)
{
    struct block_device_operations ops = { .swap_slot_free_notify = notify };
    struct gendisk disk = { .fops = &ops };
    struct block_device bdev = { .bd_disk = &disk };
    const unsigned int flags[] = {
        SWP_XSWAP | SWP_RSWAP, SWP_XSWAP, 0, SWP_BLKDEV, SWP_BLKDEV,
    };
    unsigned int i, nr;
    int failures = 0;

    for (i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        for (nr = 1; nr <= 4; nr *= 4) {
            struct swap_info_struct si = {
                .flags = flags[i], .type = 3,
                .bdev = flags[i] & SWP_BLKDEV ? &bdev : NULL,
            };
            ops.swap_slot_free_notify = i == 4 ? NULL : notify;
            first_offset = 1023;
            count = nr;
            remote = flags[i] & SWP_RSWAP;
            nr_swap_pages = 0;
            arch_calls = notify_calls = zswap_calls = 0;
            hash_invalidations = 0;
            barrier_done = false;
            swap_range_free(&si, first_offset, nr);
            if (zswap_calls != (remote ? 0 : 1)) {
                puts("FAIL: slot cleanup calls zswap for a tree-less remote device");
                failures++;
            }
            assert(hash_invalidations == (remote ? 1 : 0));
            assert(notify_calls == ((flags[i] & SWP_BLKDEV) && i != 4 ? nr : 0));
        }
    }
    if (!failures)
        puts("PASS: actual slot cleanup bypasses rswap zswap invalidation only");
    return !!failures;
}
"""


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
    sources = {
        "mm/rswap.h": (root / "mm/rswap.h").read_text(),
        "mm/rswap_backend.h": (root / "mm/rswap_backend.h").read_text(),
        "mm/rswap.c": (root / "mm/rswap.c").read_text(),
    }
    hash_len = define_number(sources["mm/rswap.h"], "RSWAP_HASH_LEN",
                             "mm/rswap.h", {})
    real = {
        "RSWAP_HASH_LEN": hash_len,
        "RSWAP_HASH_HEXLEN": define_number(
            sources["mm/rswap.c"], "RSWAP_HASH_HEXLEN", "mm/rswap.c",
            {"RSWAP_HASH_LEN": hash_len}),
        "RSWAP_KV_KEY_LEN": define_number(
            sources["mm/rswap_backend.h"], "RSWAP_KV_KEY_LEN",
            "mm/rswap_backend.h", {"RSWAP_HASH_LEN": hash_len}),
        "RSWAP_BATCH_MAX": define_number(
            sources["mm/rswap_backend.h"], "RSWAP_BATCH_MAX",
            "mm/rswap_backend.h", {}),
    }
    shims = (
        ("submit/parser shims", SHIMS,
         ("RSWAP_HASH_LEN", "RSWAP_HASH_HEXLEN", "RSWAP_KV_KEY_LEN",
          "RSWAP_BATCH_MAX")),
        ("hash shims", HASH_SHIMS,
         ("RSWAP_HASH_LEN", "RSWAP_HASH_HEXLEN", "RSWAP_KV_KEY_LEN")),
    )
    structs = (
        ("mm/rswap_backend.h", SHIMS, "rswap_kv_page"),
        ("mm/rswap.h", HASH_SHIMS, "rswap_hash"),
    )
    drift = 0
    for label, shim, names in shims:
        for name in names:
            value = define_number(shim, name, label,
                                  {"RSWAP_HASH_LEN": hash_len})
            if value != real[name]:
                print(f"FAIL: {label} define {name} is {value}, kernel says "
                      f"{real[name]}")
                drift += 1
    for source, shim, name in structs:
        want = struct_members(sources[source], name, source)
        got = struct_members(shim, name, "shim")
        if want != got:
            print(f"FAIL: shim struct {name} has members {got}, {source} has "
                  f"{want}")
            drift += 1
    if drift:
        return drift
    print("PASS: shim constants and structs match the kernel sources")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision",
                        help="test the source at a git revision; it must use "
                             "the same KV backend interface as HEAD")
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[2]
    if args.revision:
        source = subprocess.check_output(
            ["git", "show", f"{args.revision}:mm/rswap.c"],
            cwd=root, text=True)
        swapfile = subprocess.check_output(
            ["git", "show", f"{args.revision}:mm/swapfile.c"],
            cwd=root, text=True)
        http = subprocess.run(
            ["git", "show", f"{args.revision}:mm/rswap_http.c"],
            cwd=root, text=True, check=False, capture_output=True).stdout
    else:
        source = (root / "mm/rswap.c").read_text()
        http = (root / "mm/rswap_http.c").read_text()
        swapfile = (root / "mm/swapfile.c").read_text()
    if http:
        response = ("#define rswap_parse_response rswap_http_parse_response\n" +
                    extract(http, "static size_t rswap_http_header_end(",
                            "/* ---------- Backend operations ---------- */",
                            "mm/rswap_http.c: response parser"))
    else:
        # Revisions before the backend split keep the parser in rswap.c.
        response = ("#define rswap_recv rswap_sock_recv\n" +
                    extract(source, "static int rswap_parse_response(",
                            "/* ---------- Per-page digests (page_ext)",
                            "mm/rswap.c: response parser"))
    start = ("static int rswap_submit_batch(" if "static int rswap_submit_batch("
             in source else
             "static void rswap_submit(" if "static void rswap_submit(" in source
             else "static void rswap_submit_write(")
    submit = extract(source, start, "/* The rswap operations vector. */",
                     "mm/rswap.c: submit paths")
    hashes = extract(source, "static struct rswap_hash *rswap_slot_lookup(",
                     "/*\n * Resolve the digest user space supplied",
                     "mm/rswap.c: hash slots")
    hashes += extract(source, "static int rswap_page_key(",
                      "/* ---------- swap_ops implementations",
                      "mm/rswap.c: rswap_page_key")
    hashes += extract(source, "void rswap_hash_invalidate(", "int rswap_enable(",
                      "mm/rswap.c: rswap_hash_invalidate")
    free = extract(swapfile, "static void swap_range_free(",
                   "static bool get_swap_device_info(",
                   "mm/swapfile.c: swap_range_free")
    stats = extract(source, "struct rswap_stats {",
                    "/* ---------- Per-page digests (page_ext)",
                    "mm/rswap.c: stats")
    snippets = {
        "response": SHIMS + response + PARSER_MAIN,
        "folio": SHIMS + submit + BACKEND_MAIN,
        "hashes": HASH_SHIMS + hashes + HASH_MAIN,
        "free": FREE_SHIMS + free + FREE_MAIN,
        "stats": STATS_SHIMS + stats + STATS_MAIN,
    }
    failures = check_shim_drift(root)
    with tempfile.TemporaryDirectory(prefix="rswap-backend-") as directory:
        for name, snippet in snippets.items():
            path = pathlib.Path(directory) / f"{name}.c"
            path.write_text(snippet)
            executable = path.with_suffix("")
            subprocess.run(
                ["cc", "-O2", "-Wall", "-Werror",
                 "-Wno-unused-function", "-Wno-unused-variable",
                 # pr_err_ratelimited() is a no-op shim, so the entries it
                 # would print look unused here.
                 "-Wno-unused-but-set-variable", "-Wno-sign-compare",
                 str(path), "-o", str(executable)],
                check=True)
            failures += subprocess.run([str(executable)], check=False).returncode
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
