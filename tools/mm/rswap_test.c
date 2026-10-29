// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
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

int main(int argc, char **argv)
{
	struct sigaction action = {
		.sa_sigaction = sigbus_handler,
		.sa_flags = SA_SIGINFO,
	};
	size_t size = 1024 * 1024;
	size_t page_size = sysconf(_SC_PAGESIZE);
	unsigned int rounds = 3;
	uint64_t *data;
	unsigned char *resident;
	unsigned int round;
	int huge = argc > 3 && !strcmp(argv[3], "huge");
	const char *reclaim = argc > 4 ? argv[4] : NULL;
	size_t alignment = page_size;
	void *mapping;
	size_t prefix;

	if (argc > 1)
		size = strtoul(argv[1], NULL, 0) * 1024;
	if (argc > 2)
		rounds = strtoul(argv[2], NULL, 0);
	if (!size || size % page_size || !rounds) {
		fprintf(stderr, "Usage: %s [size_KiB] [rounds] [huge]\n",
			argv[0]);
		return 1;
	}
	sigaction(SIGBUS, &action, NULL);
	setvbuf(stdout, NULL, _IOLBF, 0);
	/* Reclaim must not evict the verifier's own stack and runtime state. */
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
	mapping = mmap(NULL, size + alignment, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	data = (void *)(((uintptr_t)mapping + alignment - 1) &
		       ~(alignment - 1));
	resident = calloc(size / page_size, 1);
	if (mapping == MAP_FAILED || !resident) {
		perror("allocate");
		return 1;
	}
	prefix = (char *)data - (char *)mapping;
	if (prefix)
		munmap(mapping, prefix);
	munmap((char *)data + size, alignment - prefix);
	if (madvise(data, size, huge ? MADV_HUGEPAGE : MADV_NOHUGEPAGE)) {
		perror("madvise hugepage");
		return 1;
	}
	printf("Testing %zu KiB, %zu-byte pages, %u rounds, %s\n",
	       size / 1024, page_size, rounds, huge ? "THP" : "base pages");

	for (round = 0; round < rounds; round++) {
		uint64_t seed = ((uint64_t)getpid() << 32) ^
				(uint64_t)time(NULL) ^ round;
		size_t i, evicted = 0, mismatches = 0;

		for (i = 0; i < size / sizeof(*data); i++)
			data[i] = pattern(i, seed);
		if (huge) {
			FILE *file = fopen("/proc/self/smaps", "r");
			char line[256];
			unsigned long start, end, huge_kb = 0;
			int in_mapping = 0;

			if (!file) {
				perror("smaps");
				return 1;
			}
			while (fgets(line, sizeof(line), file)) {
				if (sscanf(line, "%lx-%lx", &start, &end) == 2)
					in_mapping = (uintptr_t)data >= start &&
						     (uintptr_t)data < end;
				if (in_mapping &&
				    sscanf(line, "AnonHugePages: %lu kB",
					   &huge_kb) == 1)
					break;
			}
			fclose(file);
			printf("Round %u: %lu KiB backed by THP\n",
			       round + 1, huge_kb);
			if (!huge_kb)
				return 4;
		}
		if (madvise(data, size, MADV_PAGEOUT)) {
			perror("MADV_PAGEOUT");
			return 1;
		}
		if (reclaim) {
			FILE *file = fopen(reclaim, "w");

			if (!file) {
				perror("open memory.reclaim");
				return 1;
			}
			fprintf(file, "%zu swappiness=200\n", size);
			if (fclose(file) && errno != EAGAIN) {
				perror("memory.reclaim");
				return 1;
			}
		}
		usleep(100000);
		if (mincore(data, size, resident)) {
			perror("mincore");
			return 1;
		}
		for (i = 0; i < size / page_size; i++)
			if (!(resident[i] & 1))
				evicted++;
		printf("Round %u: %zu/%zu pages evicted\n",
		       round + 1, evicted, size / page_size);
		if (!evicted) {
			fprintf(stderr, "SKIP: no pages evicted; not a swap test\n");
			return 4;
		}
		/* Force base-page faults after a large-folio write. */
		if (huge && madvise(data, size, MADV_NOHUGEPAGE)) {
			perror("disable THP for swap-in");
			return 1;
		}
		for (i = 0; i < size / sizeof(*data); i++) {
			uint64_t expected = pattern(i, seed);
			uint64_t actual = data[i];

			if (actual == expected)
				continue;
			if (mismatches++ < 8)
				fprintf(stderr,
					"Mismatch byte %zu: expected %016" PRIx64
					", got %016" PRIx64 "\n",
					i * sizeof(*data), expected, actual);
		}
		if (mismatches) {
			fprintf(stderr, "FAIL: %zu mismatching words\n",
				mismatches);
			return 1;
		}
		printf("Round %u: all %zu bytes match\n", round + 1, size);
		if (huge && madvise(data, size, MADV_HUGEPAGE)) {
			perror("enable THP for next round");
			return 1;
		}
	}
	munmap(data, size);
	free(resident);
	puts("PASS");
	return 0;
}
