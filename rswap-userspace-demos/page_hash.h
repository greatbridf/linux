/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * page_hash.h - Definitions for the page-hash userspace tool and prototypes
 *
 * The active userspace program attaches digests through the rswap sysctl.
 * The BPF declarations are retained for the postponed eBPF prototype.
 */
#ifndef __PAGE_HASH_H
#define __PAGE_HASH_H

#define RSWAP_HASH_LEN		32
#define RSWAP_HASH_HEXLEN	(RSWAP_HASH_LEN * 2)
#define RSWAP_ATTACH_PATH	"/proc/sys/vm/rswap/attach"

/* Compatibility names used by the postponed BPF prototype. */
#define SHA256_DIGEST_LEN	RSWAP_HASH_LEN
#define HASH_SIZE		RSWAP_HASH_LEN

/* ------------------------------------------------------------------ */
/*  Per-page metadata (userspace bookkeeping)                          */
/* ------------------------------------------------------------------ */

struct page_meta {
	unsigned long  addr;                    /* page-aligned address */
	unsigned char  hash[SHA256_DIGEST_LEN]; /* SHA-256 hash */
};

/* ------------------------------------------------------------------ */
/*  BPF program context (SEC("syscall") argument)                      */
/* ------------------------------------------------------------------ */

/*
 * Context argument for the SEC("syscall") entry point.
 *
 * The BPF_PROG_TEST_RUN infrastructure copies this struct in before the
 * program runs and copies it back afterwards — so the embedded @hash
 * field lets userspace retrieve the computed digest.
 *
 * @ptr:       userspace page address (input)
 * @page_size: system page size, typically 4096 or 16384 (input)
 * @hash:      SHA-256 digest written by the BPF program (output, 32 bytes)
 */
struct get_hash_args {
	unsigned long long  ptr;
	unsigned long long  page_size;
	unsigned char       hash[SHA256_DIGEST_LEN];
};

/* ------------------------------------------------------------------ */
/*  BPF hash-map layout                                               */
/* ------------------------------------------------------------------ */

/*
 * The postponed BPF prototype uses a BPF_MAP_TYPE_HASH map named "hash_map":
 *
 *   key   -> page-aligned userspace address (u64)
 *   value -> struct page_hash_val (the SHA-256 digest)
 *
 * The prototype userspace program computes the digests with OpenSSL and
 * inserts them; the BPF program only does a map lookup.  Because no __user
 * memory is ever dereferenced inside the BPF program, the lookup works from
 * any calling context and is independent of current->mm.
 */

#define PAGE_HASH_MAP_NAME  "hash_map"
#define PAGE_HASH_MAX_ENTRIES  65536

/* bpffs paths used by the postponed prototype and its test module. */
#define PAGE_HASH_PROG_PIN  "/sys/fs/bpf/page_hash_prog"
#define PAGE_HASH_MAP_PIN   "/sys/fs/bpf/page_hash_map"

/* debugfs trigger file exported by the kernel test module. */
#define PAGE_HASH_DEBUGFS_RUN  "/sys/kernel/debug/page_hash_test/run"

struct page_hash_val {
	unsigned char hash[SHA256_DIGEST_LEN];
};

#endif /* __PAGE_HASH_H */
