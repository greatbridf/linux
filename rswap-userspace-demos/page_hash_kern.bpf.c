// SPDX-License-Identifier: GPL-2.0-only
/*
 * page_hash_kern.bpf.c -- BPF program: per-page SHA-256 lookup from a map
 *
 * == Overview ==
 *
 * This BPF program implements the function:
 *
 *   bool get_hash_for_addr(void *__user ptr, char out_hash[32]);
 *
 * Given a userspace pointer, it page-aligns the address, looks the page
 * up in the "hash_map" BPF hash map, copies the 32-byte digest into
 * @out_hash and returns 1 (true).  If the address is not present in the
 * map it returns 0 (false).
 *
 * == Why a map instead of hashing in the BPF program? ==
 *
 * Hashing page contents inside BPF requires bpf_probe_read_user(), which
 * walks *current->mm*.  That means the program only works when it runs
 * in the context of the process that owns the pages: a kernel module
 * trigger writing to debugfs from another task would see a different
 * (or empty) address space and the read would fail.
 *
 * Storing digests in a map removes the dependency on current->mm
 * entirely: the BPF program never touches user memory, so the same
 * lookup succeeds from any context (syscall, kernel thread, ...).
 *
 * The map is:
 *
 *   key   -> page-aligned address (u64)
 *   value -> struct page_hash_val { u8 hash[32] }
 *
 * Userspace populates it from OpenSSL-computed digests.
 *
 * == Entry point ==
 *
 * SEC("syscall") so it can be exercised both from userspace via
 * BPF_PROG_TEST_RUN and from kernel space via bpf_prog_run().
 */

#define SEC(NAME)         __attribute__((section(NAME), used))
#define __always_inline   inline __attribute__((always_inline))

/* BTF map-definition helpers (same shape as tools/lib/bpf/bpf_helpers.h). */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

/* Basic integer types. */
typedef unsigned char       u8;
typedef unsigned int        u32;
typedef unsigned long long  u64;

/* Pull in struct get_hash_args and struct page_hash_val. */
#include "page_hash.h"

/* ------------------------------------------------------------------ */
/*  BPF helper declarations                                           */
/* ------------------------------------------------------------------ */

/* void *bpf_map_lookup_elem(struct bpf_map *map, const void *key) -- ID 1 */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
	(void *) 1;

/* ------------------------------------------------------------------ */
/*  Map                                                               */
/* ------------------------------------------------------------------ */

struct {
	__uint(type, 1);                        /* BPF_MAP_TYPE_HASH */
	__uint(max_entries, PAGE_HASH_MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct page_hash_val);
} hash_map SEC(".maps");

/* ------------------------------------------------------------------ */
/*  Entry point                                                       */
/* ------------------------------------------------------------------ */

SEC("syscall")
int lookup_hash_entry(struct get_hash_args *ctx)
{
	struct page_hash_val *val;
	u64 page_size = ctx->page_size;
	u64 base;

	/*
	 * Align the address down to a page boundary.  Fall back to 4096 if
	 * the caller passed something that is not a sane power of two.
	 */
	if (page_size < 64 || (page_size & (page_size - 1)))
		page_size = 4096;

	base = ctx->ptr & ~(page_size - 1);

	val = bpf_map_lookup_elem(&hash_map, &base);
	if (!val)
		return 1;               /* false: address not in map */

	/* Copy the digest into the caller's context. */
#pragma clang loop unroll(full)
	for (int i = 0; i < SHA256_DIGEST_LEN; i++)
		ctx->hash[i] = val->hash[i];

	return 0;                       /* true: hash returned */
}

char _license[] SEC("license") = "GPL";
