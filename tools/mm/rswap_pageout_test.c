// SPDX-License-Identifier: GPL-2.0-only
/* One whole-mapping MADV_PAGEOUT, driven by rswap_pageout_test.py. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <openssl/evp.h>

#define RSWAP_ATTACH_PATH "/proc/sys/vm/rswap/attach"

/* A documented skip must be distinguishable from a failure. */
#define EXIT_SKIP 77

static void sigbus_handler(int sig __always_unused,
			  siginfo_t *info __always_unused,
			  void *context __always_unused)
{
	static const char msg[] = "FAIL: SIGBUS while reading swapped data\n";

	write(STDERR_FILENO, msg, sizeof(msg) - 1);
	_exit(1);
}

static uint64_t pattern(uint64_t word, uint64_t seed)
{
	uint64_t value = word + seed;

	value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
	return value ^ (value >> 31);
}

static uint64_t monotonic_ns(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now)) {
		perror("clock_gettime");
		exit(1);
	}
	return (uint64_t)now.tv_sec * 1000000000 + now.tv_nsec;
}

/* The pageout runner brackets tracing and counters with these handshakes. */
static void wait_for_runner(void)
{
	if (getchar() != 'G') {
		fprintf(stderr, "FAIL: pageout runner disconnected\n");
		exit(1);
	}
}

static int count_swapped(void *data, size_t pages, size_t page_size,
			 size_t *swapped, size_t *present)
{
	uint64_t entries[128];
	size_t offset = 0;
	int fd = open("/proc/self/pagemap", O_RDONLY);

	if (fd < 0)
		return -1;
	while (offset < pages) {
		size_t count = pages - offset, i;
		off_t pos = ((uintptr_t)data / page_size + offset) * 8;

		if (count > ARRAY_SIZE(entries))
			count = ARRAY_SIZE(entries);
		if (pread(fd, entries, count * 8, pos) != (ssize_t)(count * 8)) {
			close(fd);
			return -1;
		}
		for (i = 0; i < count; i++) {
			*swapped += !!(entries[i] & (UINT64_C(1) << 62));
			*present += !!(entries[i] & (UINT64_C(1) << 63));
		}
		offset += count;
	}
	close(fd);
	return 0;
}

static int attach_page_hashes(void *data, size_t size, size_t page_size,
			      const char *manifest)
{
	EVP_MD_CTX *ctx;
	FILE *keys;
	size_t offset;
	int fd;
	int ret = -1;

	keys = fopen(manifest, "wx");
	if (!keys) {
		perror(manifest);
		return -1;
	}
	ctx = EVP_MD_CTX_new();
	fd = open(RSWAP_ATTACH_PATH, O_WRONLY);
	if (!ctx || fd < 0) {
		perror(RSWAP_ATTACH_PATH);
		goto out;
	}

	for (offset = 0; offset < size; offset += page_size) {
		unsigned char hash[EVP_MAX_MD_SIZE];
		unsigned int hash_len;
		char hex[EVP_MAX_MD_SIZE * 2 + 1];
		char line[128];
		ssize_t written;
		size_t i, len;

		if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
		    EVP_DigestUpdate(ctx, (char *)data + offset, page_size) != 1 ||
		    EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1 ||
		    hash_len != 32) {
			fprintf(stderr, "SHA-256 failed at offset %zu\n", offset);
			goto out;
		}
		for (i = 0; i < hash_len; i++)
			snprintf(hex + i * 2, 3, "%02x", hash[i]);
		if (fprintf(keys, "%s\n", hex) < 0) {
			perror("write digest manifest");
			goto out;
		}
		len = snprintf(line, sizeof(line), "%#lx %s\n",
			       (unsigned long)((char *)data + offset), hex);
		if (len >= sizeof(line) || lseek(fd, 0, SEEK_SET) < 0) {
			perror("attach page hash");
			goto out;
		}
		do {
			written = write(fd, line, len);
		} while (written < 0 && errno == EINTR);
		if (written < 0 || (size_t)written != len) {
			perror("attach page hash");
			goto out;
		}
	}

	ret = 0;
out:
	if (fd >= 0)
		close(fd);
	EVP_MD_CTX_free(ctx);
	if (fclose(keys)) {
		perror("close digest manifest");
		ret = -1;
	}
	return ret;
}

int main(int argc, char **argv)
{
	struct sigaction action = {
		.sa_sigaction = sigbus_handler,
		.sa_flags = SA_SIGINFO,
	};
	size_t page_size = sysconf(_SC_PAGESIZE);
	size_t alignment = page_size, size, prefix, i;
	size_t evicted = 0, mismatches = 0;
	size_t swapped = 0, present = 0;
	uint64_t seed, started, elapsed;
	unsigned long long size_kib;
	unsigned char *resident;
	uint64_t *data;
	void *mapping;
	char *end;
	int huge;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s size_KiB base|huge digest_manifest\n",
			argv[0]);
		return 1;
	}
	errno = 0;
	size_kib = strtoull(argv[1], &end, 10);
	if (errno || end == argv[1] || *end || argv[1][0] == '-' ||
	    !size_kib || size_kib > SIZE_MAX / 1024 ||
	    size_kib * 1024 % page_size ||
	    (strcmp(argv[2], "base") && strcmp(argv[2], "huge"))) {
		fprintf(stderr, "Invalid size or page mode\n");
		return 1;
	}
	size = size_kib * 1024;
	huge = !strcmp(argv[2], "huge");
	sigaction(SIGBUS, &action, NULL);
	setvbuf(stdout, NULL, _IOLBF, 0);
	/* Keep the verifier's existing runtime state out of reclaim. */
	if (mlockall(MCL_CURRENT)) {
		perror("mlockall");
		return 1;
	}
	if (huge) {
		FILE *file = fopen(
			"/sys/kernel/mm/transparent_hugepage/hpage_pmd_size", "r");

		if (!file || fscanf(file, "%zu", &alignment) != 1) {
			fprintf(stderr, "Cannot read THP size\n");
			return 1;
		}
		fclose(file);
	}
	if (size > SIZE_MAX - alignment) {
		fprintf(stderr, "Mapping size overflows\n");
		return 1;
	}
	mapping = mmap(NULL, size + alignment, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	data = (void *)(((uintptr_t)mapping + alignment - 1) &
		       ~(alignment - 1));
	prefix = (char *)data - (char *)mapping;
	if (prefix)
		munmap(mapping, prefix);
	munmap((char *)data + size, alignment - prefix);
	resident = calloc(size / page_size, 1);
	if (!resident) {
		perror("calloc");
		return 1;
	}
	if (madvise(data, size, huge ? MADV_HUGEPAGE : MADV_NOHUGEPAGE)) {
		perror("madvise page mode");
		return 1;
	}
	seed = pattern(0, ((uint64_t)getpid() << 32) ^ time(NULL));
	for (i = 0; i < size / sizeof(*data); i++)
		data[i] = pattern(i, seed);
	if (attach_page_hashes(data, size, page_size, argv[3]))
		return 1;
	if (huge) {
		FILE *file = fopen("/proc/self/smaps", "r");
		unsigned long start, end, huge_kb = 0;
		int in_mapping = 0;
		char line[256];

		if (!file) {
			perror("smaps");
			return 1;
		}
		while (fgets(line, sizeof(line), file)) {
			if (sscanf(line, "%lx-%lx", &start, &end) == 2)
				in_mapping = (uintptr_t)data >= start &&
					     (uintptr_t)data < end;
			if (in_mapping &&
			    sscanf(line, "AnonHugePages: %lu kB", &huge_kb) == 1)
				break;
		}
		fclose(file);
		printf("THP KiB: %lu/%zu\n", huge_kb, size / 1024);
		if (huge_kb != size / 1024) {
			fprintf(stderr, "SKIP: mapping is not fully backed by THP\n");
			return EXIT_SKIP;
		}
	}
	printf("READY pid=%d bytes=%zu pages=%zu address=%#lx\n", getpid(),
	       size, size / page_size, (unsigned long)data);
	wait_for_runner();

	/* Exactly one call: no range splitting, retries, or memory.reclaim. */
	started = monotonic_ns();
	if (madvise(data, size, MADV_PAGEOUT)) {
		perror("MADV_PAGEOUT");
		return 1;
	}
	elapsed = monotonic_ns() - started;
	if (mincore(data, size, resident)) {
		perror("mincore");
		return 1;
	}
	for (i = 0; i < size / page_size; i++)
		if (!(resident[i] & 1))
			evicted++;
	if (count_swapped(data, size / page_size, page_size, &swapped, &present)) {
		perror("read pagemap");
		return 1;
	}
	printf("PAGEOUT ns=%" PRIu64 " nonresident=%zu pages=%zu swapped=%zu present=%zu\n",
	       elapsed, evicted, size / page_size, swapped, present);
	wait_for_runner();

	/* Check every byte even when MADV_PAGEOUT only evicted part of the VMA. */
	if (madvise(data, size, MADV_NOHUGEPAGE)) {
		perror("disable THP for swapin");
		return 1;
	}
	for (i = 0; i < size / sizeof(*data); i++) {
		uint64_t expected = pattern(i, seed);

		if (data[i] != expected && mismatches++ < 8)
			fprintf(stderr, "Mismatch at byte %zu\n", i * sizeof(*data));
	}
	printf("VERIFY bytes=%zu mismatches=%zu\n", size, mismatches);
	munmap(data, size);
	free(resident);
	if (mismatches || swapped != size / page_size || present) {
		fprintf(stderr, "FAIL: incomplete pageout or corrupt data\n");
		return 1;
	}
	puts("PASS");
	return 0;
}
