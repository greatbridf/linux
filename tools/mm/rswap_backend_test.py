#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile actual backend and slot cleanup functions with deterministic shims."""

import argparse
import pathlib
import subprocess
import tempfile


SHIMS = r"""
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
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
#define RSWAP_KV_KEY_LEN 65
#define RSWAP_BATCH_MAX 8
#define RSWAP_HTTP_MAX_HEADER 2048
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define pr_debug_ratelimited(...) do { } while (0)
#define pr_err_ratelimited(...) do { } while (0)
typedef int64_t s64;
#define ktime_get_ns() ((s64)0)
#define kmalloc(size, flags) malloc(size)
#define kfree(ptr) free(ptr)
#define kvmalloc_array(count, size, flags) calloc((count), (size))
#define kvfree(ptr) free(ptr)
#define PTR_ERR(ptr) ((long)(ptr))
#define IS_ERR(ptr) ((uintptr_t)(ptr) > (uintptr_t)-4096)
typedef struct { unsigned long val; } swp_entry_t;
struct socket { int unused; };
struct iov_iter { int unused; };
struct kiocb { void (*ki_complete)(struct kiocb *, long); };
struct page { unsigned char *data; };
struct folio {
    swp_entry_t swap;
    unsigned char *data;
    unsigned long nr_pages;
    struct page pages[16];
};
struct rswap_kv_page {
    const char *key;
    void *data;
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
static void rswap_stats_key_failure(struct rswap_stats *stats, int rw, int err)
{
    if (rw == WRITE && err == -ENODATA)
        counted.no_digest++;
    else if (rw == READ && err == -ENOENT)
        counted.no_entry++;
    rswap_stats_errors(stats, rw, 1);
}
struct swap_iocb {
    struct kiocb iocb;
    unsigned int nr_bvecs;
    size_t len;
    struct bio_vec bvecs[4];
};
struct swap_io_ctx { struct swap_iocb *sio; };
static struct socket socket_stub;
static const char *response_data;
static size_t response_size, response_offset;
static int response_error;
static long completion;
static int requests;
static int moved;
static unsigned long active_key;
static unsigned char stored[32][PAGE_SIZE * 8];
static size_t stored_len[32];
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
static struct page *folio_page(struct folio *folio, unsigned long index)
{
    return &folio->pages[index];
}
static swp_entry_t folio_swap_entry(struct folio *folio, unsigned long index)
{
    return (swp_entry_t) { .val = folio->swap.val + index };
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
static int rswap_page_key(struct swap_info_struct *si, struct page *page,
                          swp_entry_t entry, int rw, char *hex)
{
    snprintf(hex, 65, "%064lx", entry.val);
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
        active_key = strtoul(pages[i].key, NULL, 16);
        assert(active_key < 32 && len <= sizeof(stored[0]));
        memcpy(stored[active_key], pages[i].data, len);
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
        active_key = strtoul(pages[i].key, NULL, 16);
        assert(active_key < 32);
        if (stored_len[active_key] != len)
            return -ENOENT;
        memcpy(pages[i].data, stored[active_key], len);
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
    int failures = 0;
    set_response(full, sizeof(full) - 1, 0);
    assert(rswap_parse_response(&socket_stub, data, 4, true) == 0);
    assert(!memcmp(data, "ABCD", 4));
    set_response(write_ok, sizeof(write_ok) - 1, 0);
    assert(rswap_parse_response(&socket_stub, data, 4, false) == 0);
    set_response(short_body, sizeof(short_body) - 1, 0);
    if (rswap_parse_response(&socket_stub, data, 4, true) == 0) {
        puts("FAIL: premature EOF reported as a complete read");
        failures++;
    }
    set_response(wrong_length, sizeof(wrong_length) - 1, 0);
    if (rswap_parse_response(&socket_stub, data, 4, true) == 0) {
        puts("FAIL: wrong Content-Length accepted");
        failures++;
    }
    set_response(missing, sizeof(missing) - 1, 0);
    if (rswap_parse_response(&socket_stub, data, 4, true) == 0) {
        puts("FAIL: missing Content-Length accepted");
        failures++;
    }
    set_response(duplicate, sizeof(duplicate) - 1, 0);
    if (rswap_parse_response(&socket_stub, data, 4, true) == 0) {
        puts("FAIL: duplicate Content-Length accepted");
        failures++;
    }
    set_response(not_found, sizeof(not_found) - 1, 0);
    assert(rswap_parse_response(&socket_stub, data, 4, true) < 0);
    set_response(short_body, sizeof(short_body) - 1, -EAGAIN);
    if (rswap_parse_response(&socket_stub, data, 4, true) != -EAGAIN) {
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
    struct swap_io_ctx ctx = { .sio = &sio };
    size_t i;
    for (i = 0; i < sizeof(original); i++)
        original[i] = (i * 73 + i / PAGE_SIZE * 29) & 255;
    for (i = 0; i < 8; i++)
        big.pages[i].data = original + i * PAGE_SIZE;
    sio.bvecs[0] = (struct bio_vec) {
        .folio = &big, .bv_page = &big.pages[0], .bv_len = sizeof(original),
    };
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
        small.pages[0].data = small.data;
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
        struct swap_io_ctx wide_ctx = { .sio = &wide_sio };

        for (i = 0; i < sizeof(many); i++)
            many[i] = (i * 31 + i / PAGE_SIZE * 17) & 255;
        for (i = 0; i < 12; i++) {
            wide.pages[i].data = many + i * PAGE_SIZE;
            back.pages[i].data = wide_actual + i * PAGE_SIZE;
        }
        wide_sio.bvecs[0] = (struct bio_vec) {
            .folio = &wide, .bv_page = &wide.pages[0],
            .bv_len = sizeof(many),
        };
        memset(wide_actual, 0, sizeof(many));
        requests = moved = 0;
        rswap_submit_write(&wide_ctx);
        assert(completion == sizeof(many));
        if (requests != 2 || moved != 12) {
            printf("FAIL: 12 page folio stored in %d call(s) moving %d page(s),"
                   " expected 2/12\n", requests, moved);
            return 1;
        }
        wide_sio.bvecs[0] = (struct bio_vec) {
            .folio = &back, .bv_page = &back.pages[0],
            .bv_len = sizeof(many),
        };
        requests = moved = 0;
        rswap_submit_read(&wide_ctx);
        assert(completion == sizeof(many));
        if (requests != 2 || moved != 12) {
            printf("FAIL: 12 page folio read in %d call(s) moving %d page(s),"
                   " expected 2/12\n", requests, moved);
            return 1;
        }
        if (memcmp(many, wide_actual, sizeof(many))) {
            puts("FAIL: batched multi-folio round trip corrupted data");
            return 1;
        }
    }
    /* Read multiple folios in one request, with callback initialized first. */
    struct folio first = { .swap = { .val = 1 }, .data = actual };
    struct folio second = { .swap = { .val = 2 }, .data = actual + PAGE_SIZE };
    first.pages[0].data = first.data;
    second.pages[0].data = second.data;
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
        digest_ok = false;
        if (rswap_can_merge(&candidate, &previous, PAGE_SIZE, WRITE)) {
            puts("FAIL: merged a write whose pages have no digest");
            return 1;
        }
        if (!rswap_can_merge(&candidate, &previous, PAGE_SIZE, READ)) {
            puts("FAIL: write-only digest gate blocked a read merge");
            return 1;
        }
        digest_ok = true;
        entry_ok = false;
        if (rswap_can_merge(&candidate, &previous, PAGE_SIZE, READ)) {
            puts("FAIL: merged a read whose entries have no digest");
            return 1;
        }
        entry_ok = true;
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
#include <string.h>
typedef int64_t s64;
typedef struct { s64 v; } atomic64_t;
#define atomic64_read(p) ((p)->v)
#define atomic64_add(value, p) ((p)->v += (value))
#define atomic64_inc(p) ((p)->v++)
#define atomic64_cmpxchg(p, old, new)					\
	({ s64 __old = (p)->v; if (__old == (old)) (p)->v = (new); __old; })
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

    /* Only the documented failures count as no digest / no entry. */
    rswap_stats_key_failure(&stats, WRITE, -ENODATA);
    rswap_stats_key_failure(&stats, READ, -ENOENT);
    rswap_stats_key_failure(&stats, READ, -EIO);
    if (atomic64_read(&stats.no_digest) != 1 ||
        atomic64_read(&stats.no_entry) != 1 ||
        atomic64_read(&stats.errors_written) != 2 ||
        atomic64_read(&stats.errors_read) != 2) {
        puts("FAIL: key failures miscounted");
        failures++;
    }

    /* A device without counters (or no pages) must be tolerated. */
    rswap_stats_pages(NULL, WRITE, 4);
    rswap_stats_pages(&stats, WRITE, 0);
    rswap_stats_errors(NULL, READ, 4);
    rswap_stats_key_failure(NULL, WRITE, -ENODATA);
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
#define RSWAP_HTTP_MAX_HEADER 2048
#define WRITE 1
#define smp_store_release(ptr, value) \
    __atomic_store_n((ptr), (value), __ATOMIC_RELEASE)
#define smp_load_acquire(ptr) __atomic_load_n((ptr), __ATOMIC_ACQUIRE)
typedef struct { unsigned long val; } swp_entry_t;
typedef uint8_t u8;
struct page { int unused; };
struct rswap_hash_entry {
    uint8_t hash[SHA256_DIGEST_SIZE];
    uint8_t valid;
};
struct swap_info_struct {
    unsigned long max;
    struct rswap_hash_entry *rswap_hashes;
};
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
    struct rswap_hash_entry entries[4] = { };
    struct swap_info_struct si = { .max = 4, .rswap_hashes = entries };
    uint8_t first[SHA256_DIGEST_SIZE], second[SHA256_DIGEST_SIZE], actual[32];
    char expected_hex[RSWAP_SHA256_HEXLEN + 1], hex[RSWAP_SHA256_HEXLEN + 1];
    struct page page = { };
    swp_entry_t entry = { .val = 2 };
    size_t i;

    for (i = 0; i < sizeof(first); i++) {
        first[i] = i;
        second[i] = 255 - i;
    }
    assert(rswap_hash_store(&si, entry, first) == 0);
    assert(rswap_hash_load(&si, entry, actual));
    assert(!memcmp(actual, first, sizeof(actual)));
    page_hash_available = true;
    memcpy(attached_hash, first, sizeof(attached_hash));
    assert(rswap_page_key(&si, &page, entry, WRITE, expected_hex) == 0);
    assert(rswap_page_key(&si, &page, entry, 0, hex) == 0);
    assert(!strcmp(hex, expected_hex));

    assert(rswap_hash_store(&si, entry, second) == 0);
    assert(rswap_hash_load(&si, entry, actual));
    assert(!memcmp(actual, second, sizeof(actual)));
    memcpy(attached_hash, second, sizeof(attached_hash));
    entry.val = 3;
    assert(rswap_page_key(&si, &page, entry, WRITE, hex) == 0);
    assert(rswap_page_key(&si, &page, entry, 0, expected_hex) == 0);
    assert(!strcmp(hex, expected_hex));

    /* Missing user digests fail writeout, and swapin has no fallback. */
    page_hash_available = false;
    entry.val = 1;
    assert(!rswap_hash_load(&si, entry, actual));
    assert(rswap_page_key(&si, &page, entry, 0, hex) == -ENOENT);
    assert(rswap_page_key(&si, &page, entry, WRITE, hex) == -ENODATA);
    entry.val = 4;
    assert(rswap_hash_store(&si, entry, first) == -ENOENT);
    assert(!rswap_hash_load(&si, entry, actual));
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
                    http[http.index("static int rswap_http_parse_response("):
                         http.index(
                             "/* ---------- Backend operations ---------- */")])
    else:
        # Revisions before the backend split keep the parser in rswap.c.
        response = ("#define rswap_recv rswap_sock_recv\n" +
                    source[source.index("static int rswap_parse_response("):
                           source.index(
                               "/* ---------- Per-page digests (page_ext)")])
    start = ("static int rswap_submit_batch(" if "static int rswap_submit_batch("
             in source else
             "static void rswap_submit(" if "static void rswap_submit(" in source
             else "static void rswap_submit_write(")
    submit = source[source.index(start):
                    source.index("/* The rswap operations vector. */")]
    hashes = source[source.index(
        "static struct rswap_hash_entry *rswap_hash_slot("):
        source.index("/* ---------- swap_ops implementations")]
    free = swapfile[swapfile.index("static void swap_range_free("):
                    swapfile.index("static bool get_swap_device_info(")]
    snippets = {
        "response": SHIMS + response + PARSER_MAIN,
        "folio": SHIMS + submit + BACKEND_MAIN,
        "hashes": HASH_SHIMS + hashes + HASH_MAIN,
        "free": FREE_SHIMS + free + FREE_MAIN,
    }
    if "struct rswap_stats {" in source:
        stats = source[source.index("struct rswap_stats {"):
                       source.index(
                           "/* ---------- Per-page digests (page_ext)")]
        snippets["stats"] = STATS_SHIMS + stats + STATS_MAIN
    failures = 0
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
