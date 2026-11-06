// SPDX-License-Identifier: GPL-2.0-only
/*
 * page_hash_user.c - attach SHA-256 digests to mapped pages
 *
 * The program maps anonymous memory, fills it with a deterministic pattern,
 * hashes every base page, and writes each digest to the rswap sysctl:
 *
 *   <virtual-address> <sha256-hex>
 *
 * The mapping is deliberately not mlock()ed by default: a pinned mapping
 * cannot be reclaimed, so the demo could never show rswap writing the pages
 * out.  --mlock pins it instead, for measuring only the attach side.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "page_hash.h"

#define DEFAULT_SIZE_MIB	8
#define MIB_TO_BYTES		(1024UL * 1024UL)
#define ATTACH_LINE_SIZE	(2 * sizeof(unsigned long) + \
				 RSWAP_HASH_HEXLEN + 6)

static volatile sig_atomic_t keep_running = 1;

static void handle_signal(int sig)
{
	(void)sig;
	keep_running = 0;
}

static uint64_t pattern(uint64_t word, uint64_t seed)
{
	uint64_t value = word + seed;

	value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
	return value ^ (value >> 31);
}

static bool sha256_page(EVP_MD_CTX *ctx, const unsigned char *data,
			size_t len, unsigned char out[RSWAP_HASH_LEN])
{
	unsigned int out_len;

	return EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	       EVP_DigestUpdate(ctx, data, len) == 1 &&
	       EVP_DigestFinal_ex(ctx, out, &out_len) == 1 &&
	       out_len == RSWAP_HASH_LEN;
}

static void hash_to_hex(const unsigned char hash[RSWAP_HASH_LEN],
			char hex[RSWAP_HASH_HEXLEN + 1])
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < RSWAP_HASH_LEN; i++) {
		hex[i * 2] = digits[hash[i] >> 4];
		hex[i * 2 + 1] = digits[hash[i] & 0xf];
	}
	hex[RSWAP_HASH_HEXLEN] = '\0';
}

static bool attach_hash(int fd, unsigned long addr,
			const unsigned char hash[RSWAP_HASH_LEN])
{
	char hex[RSWAP_HASH_HEXLEN + 1];
	char line[ATTACH_LINE_SIZE];
	ssize_t written;
	size_t len;

	hash_to_hex(hash, hex);
	len = snprintf(line, sizeof(line), "%#lx %s\n", addr, hex);
	if (len >= sizeof(line)) {
		errno = EOVERFLOW;
		return false;
	}
	if (lseek(fd, 0, SEEK_SET) < 0)
		return false;

	do {
		written = write(fd, line, len);
	} while (written < 0 && errno == EINTR);

	if (written < 0)
		return false;
	if ((size_t)written != len) {
		errno = EIO;
		return false;
	}
	return true;
}

static void print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [size_MiB] [--mlock]\n"
		"\n"
		"Default size: %d MiB\n"
		"The mapping is not mlocked, so rswap can reclaim it.  --mlock pins\n"
		"it in RAM instead, which keeps writeout from happening.\n",
		prog, DEFAULT_SIZE_MIB);
}

static int parse_args(int argc, char **argv, size_t *size_mib, bool *mlock)
{
	unsigned long long value = DEFAULT_SIZE_MIB;
	const char *size_arg = NULL;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--mlock")) {
			if (*mlock)
				return -1;
			*mlock = true;
			continue;
		}
		if (size_arg || argv[i][0] == '-')
			return -1;
		size_arg = argv[i];
	}

	if (size_arg) {
		char *end;

		errno = 0;
		value = strtoull(size_arg, &end, 10);
		if (errno || end == size_arg || *end || !value ||
		    value > SIZE_MAX / MIB_TO_BYTES) {
			fprintf(stderr, "Invalid size: %s\n", size_arg);
			return -1;
		}
	}

	*size_mib = value;
	return 0;
}

int main(int argc, char **argv)
{
	unsigned char *mapping = MAP_FAILED;
	unsigned char first_hash[RSWAP_HASH_LEN] = { 0 };
	EVP_MD_CTX *ctx = NULL;
	size_t size_mib;
	bool mlock_mapping = false;
	long page_size;
	size_t nr_pages;
	size_t region_size;
	uint64_t seed;
	size_t i;
	int attach_fd = -1;
	int ret = 1;

	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(stderr, NULL, _IOLBF, 0);

	if (parse_args(argc, argv, &size_mib, &mlock_mapping)) {
		print_usage(argv[0]);
		return 1;
	}

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) {
		perror("sysconf(_SC_PAGESIZE)");
		return 1;
	}

	nr_pages = size_mib * MIB_TO_BYTES / (size_t)page_size;
	region_size = nr_pages * (size_t)page_size;
	printf("=== rswap page hash attach ===\n");
	printf("  Region      : %zu MiB (%zu pages, %ld-byte pages)\n",
	       size_mib, nr_pages, page_size);
	printf("  Sysctl      : %s\n", RSWAP_ATTACH_PATH);
	printf("  mlock       : %s\n", mlock_mapping ? "yes" : "no");

	attach_fd = open(RSWAP_ATTACH_PATH, O_WRONLY);
	if (attach_fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n",
			RSWAP_ATTACH_PATH, strerror(errno));
		goto out;
	}

	mapping = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED) {
		perror("mmap");
		goto out;
	}
	printf("  Mapping     : %p .. %p\n", mapping,
	       mapping + region_size - 1);

	if (mlock_mapping && mlock(mapping, region_size))
		fprintf(stderr, "  Warning: mlock: %s\n", strerror(errno));

	seed = (uint64_t)getpid() ^ UINT64_C(0xdeadbeefcafe);
	for (i = 0; i < region_size / sizeof(uint64_t); i++)
		((uint64_t *)mapping)[i] = pattern(i, seed);
	printf("  Pattern     : seeded with %#llx\n",
	       (unsigned long long)seed);

	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Cannot allocate an OpenSSL digest context\n");
		goto out;
	}

	printf("  Attaching   : 0/%zu", nr_pages);
	for (i = 0; i < nr_pages; i++) {
		unsigned char hash[RSWAP_HASH_LEN];
		unsigned long addr = (unsigned long)(mapping + i * page_size);

		if (!sha256_page(ctx, mapping + i * page_size, page_size, hash)) {
			fprintf(stderr, "\nCannot hash page %zu\n", i);
			goto out;
		}
		if (!attach_hash(attach_fd, addr, hash)) {
			fprintf(stderr, "\nCannot attach page %zu at %#lx: %s\n",
				i, addr, strerror(errno));
			goto out;
		}
		if (!i)
			memcpy(first_hash, hash, sizeof(first_hash));
	}
	printf("\r  Attached    : %zu/%zu pages\n", nr_pages, nr_pages);

	printf("  Hash[0]     : ");
	for (i = 0; i < RSWAP_HASH_LEN; i++)
		printf("%02x", first_hash[i]);
	printf("\n");

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	printf("Press Ctrl+C to release the mapping.\n");
	while (keep_running)
		sleep(1);

	ret = 0;
out:
	if (ctx)
		EVP_MD_CTX_free(ctx);
	if (mapping != MAP_FAILED)
		munmap(mapping, region_size);
	if (attach_fd >= 0)
		close(attach_fd);
	return ret;
}
