// SPDX-License-Identifier: GPL-2.0-only
/*
 * page_hash_user.c — Userspace program for page-hashing demo
 *
 * == Overview ==
 *
 * This program performs the four requested steps:
 *
 *   1. mmap a block of anonymous memory and write a deterministic data
 *      pattern to each page.
 *   2. Allocate per-page metadata (struct page_meta) storing the page
 *      address.
 *   3. Compute the SHA-256 hash of every page using libcrypto (OpenSSL)
 *      and store it in the metadata array.
 *   4. Load the pre-compiled BPF program (page_hash_kern.bpf.o), then
 *      invoke it on each page via BPF_PROG_TEST_RUN and verify that the
 *      hash computed on-the-fly by the BPF program (using
 *      bpf_probe_read_user() to fetch page data from userspace) matches
 *      the OpenSSL-computed hash.
 *
 * The BPF program itself implements:
 *
 *   bool get_hash_for_addr(void *__user ptr, char out_hash[32]);
 *
 * See page_hash_kern.bpf.c for the full implementation.
 *
 * == Usage ==
 *
 *   ./page_hash_user [size_MiB]
 *
 *   size_MiB  — size of the mmap region in mebibytes (default 8)
 *
 * The program must be run as root (or with CAP_BPF) to load the BPF
 * program and execute BPF_PROG_TEST_RUN.
 *
 * == Build ==
 *
 *   make all
 *
 * Requires: clang (BPF target), libssl-dev, libelf-dev, libz-dev, libbpf.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <openssl/evp.h>

#include "page_hash.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                         */
/* ------------------------------------------------------------------ */

#define DEFAULT_SIZE_MIB  8

/* ------------------------------------------------------------------ */
/*  Signal handling                                                   */
/* ------------------------------------------------------------------ */

static volatile bool keep_running = true;

static void handle_signal(int sig)
{
	(void)sig;
	keep_running = false;
}

/* ------------------------------------------------------------------ */
/*  Deterministic pattern (same pattern as tools/mm/rswap_test.c)     */
/* ------------------------------------------------------------------ */

static uint64_t pattern(uint64_t word, uint64_t seed)
{
	uint64_t value = word + seed;

	value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
	return value ^ (value >> 31);
}

/* ------------------------------------------------------------------ */
/*  SHA-256 via OpenSSL                                               */
/* ------------------------------------------------------------------ */

static bool sha256_page(const unsigned char *page_data, size_t page_size,
			unsigned char out_hash[HASH_SIZE])
{
	EVP_MD_CTX *mdctx;
	unsigned int md_len;
	bool ok = false;

	mdctx = EVP_MD_CTX_new();
	if (!mdctx)
		return false;

	if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(mdctx, page_data, page_size) == 1 &&
	    EVP_DigestFinal_ex(mdctx, out_hash, &md_len) == 1 &&
	    md_len == HASH_SIZE)
		ok = true;

	EVP_MD_CTX_free(mdctx);
	return ok;
}

/* Print a hash to stderr as hex. */
static void print_hash(const unsigned char h[HASH_SIZE])
{
	for (int i = 0; i < HASH_SIZE; i++)
		fprintf(stderr, "%02x", h[i]);
}

/* Compare two hashes; return true if identical. */
static bool hash_eq(const unsigned char a[HASH_SIZE],
		    const unsigned char b[HASH_SIZE])
{
	return memcmp(a, b, HASH_SIZE) == 0;
}

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	size_t size_mib  = argc > 1 ? strtoul(argv[1], NULL, 10) : DEFAULT_SIZE_MIB;
	const size_t page_size   = sysconf(_SC_PAGESIZE);
	const size_t nr_pages    = (size_mib << 20) / page_size;
	const size_t region_size = nr_pages * page_size;

	unsigned char *mapping  = NULL;
	struct page_meta *meta  = NULL;
	struct bpf_object *obj  = NULL;
	int prog_fd             = -1;
	int ret                 = 0;
	size_t i;

	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(stderr, NULL, _IOLBF, 0);

	signal(SIGINT,  handle_signal);
	signal(SIGTERM, handle_signal);

	printf("=== Page Hash BPF Demo (on-the-fly SHA-256) ===\n");
	printf("  Region size : %zu MiB (%zu pages, %zu KiB total)\n",
	       size_mib, nr_pages, region_size / 1024);
	printf("  Page size   : %zu bytes\n", page_size);

	/* --------------------------------------------------------------- */
	/*  1. mmap anonymous memory and fill with pattern                  */
	/* --------------------------------------------------------------- */

	mapping = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	printf("  Mapping     : %p .. %p\n", (void *)mapping,
	       (void *)((unsigned char *)mapping + region_size - 1));

	/* Lock so pages stay resident. */
	if (mlock(mapping, region_size))
		perror("  (mlock non-fatal)");

	const uint64_t seed = (uint64_t)getpid() ^ (uint64_t)0xdeadbeefcafeULL;
	for (size_t j = 0; j < region_size / sizeof(uint64_t); j++)
		((uint64_t *)mapping)[j] = pattern(j, seed);

	printf("  Data written: deterministic pattern (seed=%#lx)\n", seed);

	/* --------------------------------------------------------------- */
	/*  2–3. Allocate metadata and compute SHA-256 with OpenSSL        */
	/* --------------------------------------------------------------- */

	meta = calloc(nr_pages, sizeof(*meta));
	if (!meta) {
		perror("calloc");
		ret = 1;
		goto cleanup;
	}

	printf("  Computing SHA-256 (userspace, OpenSSL)... ");
	fflush(stdout);
	/* We hash a fixed 4096-byte window per page (matching the BPF
	 * program's HASH_WINDOW).  This avoids verifier loop-limit issues
	 * on systems with 16K or 64K pages.
	 */
#define HASH_WINDOW  4096ul

	for (i = 0; i < nr_pages; i++) {
		meta[i].addr = (unsigned long)(mapping + i * page_size);
		if (!sha256_page(mapping + i * page_size, HASH_WINDOW,
				 meta[i].hash)) {
			fprintf(stderr, "\n  ERROR: SHA-256 failed at page %zu\n", i);
			ret = 1;
			goto cleanup;
		}
	}
	printf("done.\n");

	fprintf(stderr, "  Hash[0]     : ");
	print_hash(meta[0].hash);
	fprintf(stderr, "\n");

	/* --------------------------------------------------------------- */
	/*  4. Load BPF program and verify on-the-fly computation          */
	/* --------------------------------------------------------------- */

	obj = bpf_object__open_file("page_hash_kern.bpf.o", NULL);
	if (!obj) {
		fprintf(stderr, "ERROR: cannot open page_hash_kern.bpf.o\n");
		ret = 1;
		goto cleanup;
	}

	ret = bpf_object__load(obj);
	if (ret) {
		fprintf(stderr, "ERROR: bpf_object__load: %s\n", strerror(-ret));
		ret = 1;
		goto cleanup;
	}
	printf("  BPF object  : loaded successfully\n");

	{
		struct bpf_program *prog;

		prog = bpf_object__find_program_by_name(obj, "lookup_hash_entry");
		if (!prog) {
			fprintf(stderr, "ERROR: cannot find prog 'lookup_hash_entry'\n");
			ret = 1;
			goto cleanup;
		}
		prog_fd = bpf_program__fd(prog);
	}
	printf("  BPF prog fd : %d\n", prog_fd);

	/* --------------------------------------------------------------- */
	/*  Verify — call the BPF program on every page and compare hashes  */
	/* --------------------------------------------------------------- */

	printf("\n  Verifying BPF on-the-fly hash vs OpenSSL...\n");
	fflush(stdout);

	int           errors  = 0;

	for (i = 0; i < nr_pages; i++) {
		/* Prepare test-run context.
		 *
		 * IMPORTANT: bpf_prog_test_run_syscall() rejects any test run
		 * that sets ctx_out, duration, repeat, flags, or batch_size.
		 * It writes the context back to *ctx_in* in-place (the same
		 * buffer).  So we use one buffer for both input and output.
		 */
		struct get_hash_args args = {
			.ptr      = meta[i].addr,
			.page_size = HASH_WINDOW,
		};
		struct bpf_test_run_opts opts = {
			.sz           = sizeof(opts),
			.ctx_in       = &args,
			.ctx_size_in  = sizeof(args),
			.ctx_out      = NULL,
			.ctx_size_out = 0,
			.repeat       = 0,
		};
		unsigned char bpf_hash[HASH_SIZE];
		int bpf_ret;

		/* Run the BPF program. */
		ret = bpf_prog_test_run_opts(prog_fd, &opts);
		if (ret) {
			fprintf(stderr, "\n  ERROR: BPF_PROG_TEST_RUN failed at "
				"page %zu: %s\n", i, strerror(-ret));
			errors++;
			continue;
		}

		bpf_ret = opts.retval;
		/* The hash was written back into args.hash (same buffer). */
		memcpy(bpf_hash, args.hash, HASH_SIZE);

		/* Compare. */
		if (bpf_ret != 0) {
			fprintf(stderr, "\n  ERROR: BPF prog returned %d at "
				"page %zu (should be 0)\n", bpf_ret, i);
			errors++;
			continue;
		}

		if (!hash_eq(bpf_hash, meta[i].hash)) {
			fprintf(stderr, "\n  MISMATCH at page %zu:\n"
				"    OpenSSL  : ", i);
			print_hash(meta[i].hash);
			fprintf(stderr, "\n    BPF      : ");
			print_hash(bpf_hash);
			fprintf(stderr, "\n");
			errors++;
			if (errors >= 3) {
				fprintf(stderr, "  (too many errors, aborting)\n");
				ret = 1;
				goto cleanup;
			}
		}

		if (i < 5 || i == nr_pages - 1) {
			printf("  Page %5zu @ %#lx: %s\n",
			       i, meta[i].addr,
			       hash_eq(bpf_hash, meta[i].hash) ? "MATCH" : "MISMATCH");
		}
	}
	if (nr_pages > 5)
		printf("  ... (first 5 pages shown, %zu total)\n", nr_pages);

	/* --------------------------------------------------------------- */
	/*  Summary                                                        */
	/* --------------------------------------------------------------- */

	printf("\n  === Results ===\n");
	if (errors == 0) {
		printf("  All %zu pages: BPF on-the-fly SHA-256 matches OpenSSL.\n",
		       nr_pages);
	} else {
		printf("  %d / %zu pages had mismatches.\n", errors, nr_pages);
		ret = 1;
	}

	/* --------------------------------------------------------------- */
	/*  Done — keep the mapping alive until Ctrl+C                     */
	/* --------------------------------------------------------------- */

	/* Also write a test to the kernel module's debugfs file (if loaded).
	 * This exercises the kernel-module path from the correct process context
	 * so that bpf_probe_read_user() can access our mmap'd pages.
	 */
	{
		char cmd[512];
		int dbg_fd = open("/sys/kernel/debug/page_hash_test/run", O_WRONLY);

		if (dbg_fd >= 0) {
			/* Format: "<addr> <expected-hex-hash>" */
			snprintf(cmd, sizeof(cmd), "%#lx %s\n",
				 meta[0].addr, "" /* filled below */);
			/* Append the hex hash. */
			{
				char *p = cmd + strlen(cmd);
				for (int i = 0; i < 32; i++)
					p += sprintf(p, "%02x", meta[0].hash[i]);
				*p++ = '\n';
				*p = '\0';
			}
			ret = write(dbg_fd, cmd, strlen(cmd));
			if (ret < 0)
				perror("  WARNING: debugfs write");
			else
				printf("  Debugfs test  : written (check dmesg)\n");
			close(dbg_fd);
		}
	}

	printf("\n  Press Ctrl+C to release memory and cleanup.\n");
	fflush(stdout);
	while (keep_running)
		pause();

cleanup:
	printf("\n  Cleaning up...\n");
	if (obj)
		bpf_object__close(obj);
	free(meta);
	if (mapping && mapping != MAP_FAILED)
		munmap(mapping, region_size);
	printf("  Done.\n");
	return ret;
}
