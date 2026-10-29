/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * page_hash.h — Shared type definitions for the page-hash BPF demo
 *
 * This header is designed to be included by both the BPF program
 * (page_hash_kern.bpf.c) and the userspace program (page_hash_user.c).
 */
#ifndef __PAGE_HASH_H
#define __PAGE_HASH_H

/* SHA-256 produces 32 bytes */
#define SHA256_DIGEST_LEN  32

/* Compatibility alias for userspace code that still uses HASH_SIZE. */
#ifndef HASH_SIZE
#define HASH_SIZE  SHA256_DIGEST_LEN
#endif

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

#endif /* __PAGE_HASH_H */
