// SPDX-License-Identifier: GPL-2.0-only
/* Cold remote swapin performance, driven by rswap_swapin_test.py. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <pthread.h>
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

/* The runner brackets the measured swapin with these handshakes. */
static void wait_for_runner(void)
{
	if (getchar() != 'G') {
		fprintf(stderr, "FAIL: swapin runner disconnected\n");
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

#define MAX_WORKERS 32

/*
 * Upper bound on waiting for the remote reads a submission queued.  512 MiB
 * over a slow path takes tens of seconds; the runner enforces the real
 * timeout, this only keeps a broken kernel from spinning forever.
 */
#define COMPLETION_TIMEOUT_NS	(600ULL * 1000000000)

struct reader {
	uint64_t *data;
	size_t bytes;
	size_t page_size;
	pthread_barrier_t *barrier;
	int willneed;
	int error;
	uint64_t ns;
	uint64_t checksum;
};

static void *read_pages(void *arg)
{
	struct reader *reader = arg;
	uint64_t started, checksum = 0;
	size_t offset;

	pthread_barrier_wait(reader->barrier);
	started = monotonic_ns();
	if (reader->willneed) {
		if (madvise(reader->data, reader->bytes, MADV_WILLNEED))
			reader->error = errno;
	} else {
		/* One load per native page forces every missing page in. */
		for (offset = 0; offset < reader->bytes; offset += reader->page_size)
			checksum ^= *(uint64_t *)((char *)reader->data + offset);
	}
	reader->checksum = checksum;
	reader->ns = monotonic_ns() - started;
	return NULL;
}

static size_t nonresident(void *data, size_t size, size_t page_size,
			  unsigned char *resident)
{
	size_t i, missing = 0;

	if (mincore(data, size, resident)) {
		perror("mincore");
		exit(1);
	}
	for (i = 0; i < size / page_size; i++)
		missing += !(resident[i] & 1);
	return missing;
}

/*
 * Drop swap-cache residency before measuring.  memory.reclaim reports EAGAIN
 * when it reclaimed only part of the request, which is a normal outcome here;
 * read errno only from the call that failed so a stale value cannot mask a
 * real error or hide behind EAGAIN.
 */
static int reclaim_memory(const char *path, size_t size)
{
	FILE *reclaim;
	int error = 0;

	reclaim = fopen(path, "w");
	if (!reclaim) {
		perror("memory.reclaim");
		return -1;
	}
	errno = 0;
	if (fprintf(reclaim, "%zu swappiness=200\n", size) < 0)
		error = errno ? errno : EIO;
	errno = 0;
	if (fclose(reclaim) && !error)
		error = errno ? errno : EIO;
	if (error && error != EAGAIN) {
		errno = error;
		perror("memory.reclaim");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct sigaction action = {
		.sa_sigaction = sigbus_handler,
		.sa_flags = SA_SIGINFO,
	};
	struct reader readers[MAX_WORKERS] = {};
	pthread_t threads[MAX_WORKERS];
	pthread_barrier_t barrier;
	size_t page_size = sysconf(_SC_PAGESIZE);
	size_t size, pages, i, missing, swapped = 0, present = 0;
	size_t mismatches = 0;
	unsigned long long size_kib;
	unsigned long workers;
	uint64_t seed, started, submitted, loaded, verify_ns;
	unsigned char *resident;
	uint64_t *data;
	char *end;
	int willneed, error;

	if (argc != 6) {
		fprintf(stderr,
			"Usage: %s size_KiB willneed|fault workers digest_manifest memory.reclaim\n",
			argv[0]);
		return 1;
	}
	errno = 0;
	size_kib = strtoull(argv[1], &end, 10);
	if (errno || end == argv[1] || *end || argv[1][0] == '-' ||
	    !size_kib || size_kib > SIZE_MAX / 1024 ||
	    size_kib * 1024 % page_size) {
		fprintf(stderr, "Invalid mapping size\n");
		return 1;
	}
	errno = 0;
	workers = strtoul(argv[3], &end, 10);
	if (errno || end == argv[3] || *end || !workers || workers > MAX_WORKERS ||
	    (strcmp(argv[2], "willneed") && strcmp(argv[2], "fault"))) {
		fprintf(stderr, "Invalid mode or worker count\n");
		return 1;
	}
	size = size_kib * 1024;
	pages = size / page_size;
	if (pages < workers || pages % workers) {
		fprintf(stderr, "Page count must divide equally among workers\n");
		return 1;
	}
	willneed = !strcmp(argv[2], "willneed");
	sigaction(SIGBUS, &action, NULL);
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (mlockall(MCL_CURRENT)) {
		perror("mlockall");
		return 1;
	}
	data = mmap(NULL, size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	resident = calloc(pages, 1);
	if (data == MAP_FAILED || !resident) {
		perror("allocate");
		return 1;
	}
	if (madvise(data, size, MADV_NOHUGEPAGE)) {
		perror("MADV_NOHUGEPAGE");
		return 1;
	}
	seed = pattern(0, ((uint64_t)getpid() << 32) ^ time(NULL));
	for (i = 0; i < size / sizeof(*data); i++)
		data[i] = pattern(i, seed);
	if (attach_page_hashes(data, size, page_size, argv[4]))
		return 1;
	printf("PREPARE pid=%d bytes=%zu pages=%zu\n", getpid(), size, pages);
	if (madvise(data, size, MADV_PAGEOUT)) {
		perror("MADV_PAGEOUT");
		return 1;
	}
	/* Drop the swap-cache residency left by MADV_PAGEOUT before measuring. */
	if (reclaim_memory(argv[5], size))
		return 1;
	missing = nonresident(data, size, page_size, resident);
	if (count_swapped(data, pages, page_size, &swapped, &present)) {
		perror("pagemap");
		return 1;
	}
	printf("COLD nonresident=%zu swapped=%zu present=%zu pages=%zu\n",
	       missing, swapped, present, pages);
	if (missing != pages || swapped != pages || present) {
		fprintf(stderr, "FAIL: mapping is not fully evicted\n");
		return 1;
	}
	error = pthread_barrier_init(&barrier, NULL, workers + 1);
	if (error) {
		fprintf(stderr, "pthread_barrier_init: %s\n", strerror(error));
		return 1;
	}
	for (i = 0; i < workers; i++) {
		readers[i] = (struct reader) {
			.data = (void *)((char *)data + size / workers * i),
			.bytes = size / workers,
			.page_size = page_size,
			.barrier = &barrier,
			.willneed = willneed,
		};
		error = pthread_create(&threads[i], NULL, read_pages, &readers[i]);
		if (error) {
			fprintf(stderr, "pthread_create: %s\n", strerror(error));
			return 1;
		}
	}
	printf("READY pid=%d bytes=%zu pages=%zu address=%#lx workers=%lu willneed=%d\n",
	       getpid(), size, pages, (unsigned long)data, workers, willneed);
	wait_for_runner();
	started = monotonic_ns();
	pthread_barrier_wait(&barrier);
	for (i = 0; i < workers; i++)
		pthread_join(threads[i], NULL);
	submitted = monotonic_ns() - started;
	missing = nonresident(data, size, page_size, resident);
	printf("SUBMITTED ns=%" PRIu64 " nonresident=%zu pages=%zu\n",
	       submitted, missing, pages);

	/*
	 * mincore() reports a swap-cache folio as resident only once it is
	 * uptodate, which swap_read_end() sets when the remote read of that
	 * folio completed.  Waiting here, after submission returned, is what
	 * turns a WILLNEED call into a real completion gate on an asynchronous
	 * backend instead of a submission-time snapshot.
	 */
	for (;;) {
		missing = nonresident(data, size, page_size, resident);
		if (!missing || monotonic_ns() - started > COMPLETION_TIMEOUT_NS)
			break;
		usleep(200);
	}
	loaded = monotonic_ns() - started;
	printf("LOADED ns=%" PRIu64 " nonresident=%zu pages=%zu\n",
	       loaded, missing, pages);
	for (i = 0; i < workers; i++)
		printf("WORKER index=%zu ns=%" PRIu64 " error=%d checksum=%" PRIu64 "\n",
		       i, readers[i].ns, readers[i].error, readers[i].checksum);
	wait_for_runner();

	/* This time is separate from prefetch/page-touch time. */
	started = monotonic_ns();
	for (i = 0; i < size / sizeof(*data); i++) {
		uint64_t expected = pattern(i, seed);

		if (data[i] != expected && mismatches++ < 8)
			fprintf(stderr, "Mismatch at byte %zu\n", i * sizeof(*data));
	}
	verify_ns = monotonic_ns() - started;
	printf("VERIFY ns=%" PRIu64 " bytes=%zu mismatches=%zu\n",
	       verify_ns, size, mismatches);
	munmap(data, size);
	free(resident);
	pthread_barrier_destroy(&barrier);
	for (i = 0; i < workers; i++)
		if (readers[i].error)
			return 1;
	if (mismatches || missing) {
		fprintf(stderr, "FAIL: incomplete swapin or corrupt data\n");
		return 1;
	}
	puts("PASS");
	return 0;
}
