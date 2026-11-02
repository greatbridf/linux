# Remote Swap (rswap) Agent Guide

This file applies to the whole repository. It records the rswap-specific
architecture, invariants, interfaces, test workflow, and kernel contribution
rules that future coding agents must preserve.

## Non-Negotiable Invariant

**Never calculate or derive an rswap page key from a swap entry in the
kernel.**

User space hashes page contents and supplies the SHA-256 digest. The kernel
must not run a hash function over `swp_entry_t`, the page contents, or any
other kernel-derived value to create a key.

Writeout behavior is strict:

1. Read the userspace digest from `page_ext`.
2. Store that digest in the rswap device table at the page's swap offset.
3. Use only that stored digest as the HTTP KV key.

If no digest is attached, writeout fails with `-ENODATA`. Do not add a
fallback key. Swapin reads only the per-entry table and fails with `-ENOENT`
if no digest was stored.

An earlier implementation incorrectly hashed swap entries. That behavior was
removed in commit `e254942f9d5ac ("mm: rswap: use userspace provided hash
only")` and must not return.

## Project Purpose

rswap is a fileless xswap backend that stores swap pages in an external
key-value store. Each base page is stored under a SHA-256 hex key supplied by
user space for that page.

The store is reached through a pluggable KV backend. The core (`mm/rswap.c`)
owns the keys, the page_ext digests, the per-device table and the `swap_ops`
wiring; a backend only moves one page image to and from the store. Two
backends ship with the kernel:

- `http` (`mm/rswap_http.c`): HTTP/1.0 `POST`/`GET` to a userspace
  `kvswap_server` that stores one file per key.
- `redis` (`mm/rswap_redis.c`): RESP `SET`/`GET` against a Redis server, using
  the same SHA-256 hex keys, so server contents can be audited against the
  userspace digests.

Both are deliberately simple:

- One connection per `->store()`/`->load()` call and nothing cached across
  calls, so no locking is needed in the swap I/O path. The core hands a
  backend up to `RSWAP_BATCH_MAX` (8) pages at a time, which the Redis backend
  pipelines into a single write; HTTP/1.0 carries one object per request and
  turns a batch into a sequence of requests.
- The endpoint is a boot parameter; the defaults are `127.0.0.1:6789` (HTTP)
  and `127.0.0.1:6379` (Redis).
- No payload encryption and no persistence guarantees beyond the backend
  implementation. The HTTP server has no authentication at all; Redis uses
  `AUTH` and `SELECT` when a password resp. a database number is configured.
- eBPF integration is postponed and is not part of the active build.

## Architecture

### Userspace

`rswap-userspace-demos/page_hash_user.c`:

- maps anonymous memory;
- fills it with a deterministic pattern;
- computes SHA-256 over every native base page using OpenSSL;
- writes every digest to `/proc/sys/vm/rswap/attach`;
- keeps the mapping alive while the test is active.

The attach input is:

```text
<virtual-address> <64 lowercase-or-uppercase hexadecimal SHA-256 digits>
```

The virtual address must refer to an anonymous page in the writing process.
The interface is write-only and root/CAP_SYS_ADMIN protected.

The userspace tool seeks its sysctl descriptor to offset zero before each
write. This lets one descriptor issue multiple command writes.

### Kernel Entry Point

`mm/rswap.c` is the core implementation. It contains:

- swap page I/O through the `swap_ops` interface;
- the `/proc/sys/vm/rswap/attach` sysctl;
- page_ext digest access;
- per-device swap-offset hash storage;
- backend selection and the boot parameters below;
- debugfs backend, endpoint and per-device port reporting.

`mm/rswap_backend.h` defines the pluggable interface and the shared TCP
transport helpers in `mm/rswap_sock.c`. A backend is:

```c
struct rswap_backend {
        const char      *name;
        const char      *description;
        const char      *default_host;
        u16             default_port;
        unsigned int    default_send_timeout_ms;
        unsigned int    default_recv_timeout_ms;
        int             (*init)(const struct rswap_kv_config *cfg);
        int             (*store)(struct rswap_kv_page *pages, unsigned int nr,
                                 size_t len);
        int             (*load)(struct rswap_kv_page *pages, unsigned int nr,
                                size_t len);
};

struct rswap_kv_page {
        const char      *key;   /* 64 digit hex SHA-256 */
        void            *data;  /* one base page image */
};
```

The core resolves every default before `->init()`, so a backend only ever
sees final values. `->store()`/`->load()` move `nr` (1..`RSWAP_BATCH_MAX`)
page images of `len` bytes each; keys are only valid during the call. A
backend should spend one round trip per batch, not per page: a remote store
charges milliseconds per round trip, so batching is what makes it usable.

They run in swap I/O context under `GFP_NOIO`, may sleep, and must not touch
the filesystem. `->load()` returns `-ENOENT` for a missing key and rejects an
object whose length is not exactly one base page. On error the whole swap
request fails.

Backends are chosen at boot, never at runtime: switching a live device to a
different store would strand every page already written to the old one.

```text
rswap.backend=http|redis          default http
rswap.host=<address>              empty selects the backend default
rswap.port=<port>                 0 selects the backend default
rswap.redis_user=<acl user>       empty uses the Redis default user
rswap.redis_password=<secret>     empty sends no AUTH
rswap.redis_db=<n>                Redis database number
rswap.send_timeout_ms=<ms>        0 selects the backend default
rswap.recv_timeout_ms=<ms>        0 selects the backend default
```

The secrets are boot parameters only; `rswap.redis_password` is deliberately
not exposed in sysfs and must not be committed to the tree.

The RSWAP Kconfig option is defined in `mm/Kconfig` and depends on:

- `XSWAP`
- `INET`
- `SYSCTL`

It selects `PAGE_EXTENSION` and `CRYPTO_LIB_SHA256`. `RSWAP_KV_HTTP`
(default y) and `RSWAP_KV_REDIS` (default n) build the individual backends;
at least one is required.

### Page-Ext Stage

Before writeout, a page's userspace digest lives in page_ext:

```text
struct rswap_page_ext {
        u8 hash[32];
        bool valid;
};
```

The page-ext client is registered in `mm/page_ext.c`, declared in
`include/linux/page_ext.h`, and selected by `CONFIG_RSWAP`.

Access to the page digest is serialized by `rswap_hash_lock`, a global
spinlock for the short protected copy. Page-ext metadata is not assumed to
stay with one physical page forever:

- `rswap_page_ext_copy()` preserves the digest during folio migration.
- `rswap_page_ext_reset()` clears stale metadata when a page is freed.

`mm/migrate.c` invokes the copy hook. `mm/page_alloc.c` invokes the reset
hook on normal and hardware-poisoned page free paths.

### Per-Device Entry Table

page_ext alone is insufficient on swapin. A swap-cache page may have been
evicted, so its original `struct page` and page-ext data may no longer exist.

`struct swap_info_struct` therefore owns an rswap table:

```text
struct rswap_hash_entry {
        u8 hash[32];
        u8 valid;
};
```

The table is indexed directly by `swp_offset(entry)` and is allocated with
`kvcalloc(si->max, sizeof(*si->rswap_hashes), GFP_KERNEL)`. The valid byte
makes the table 33 bytes per swap slot for the current layout.

Writeout:

1. Resolve each base page and its precise swap entry.
2. Read the page-ext digest.
3. Return `-ENODATA` if the page has no attached digest.
4. Copy the digest into `si->rswap_hashes[swp_offset(entry)]`.
5. Publish validity with release semantics.
6. POST the page using the stored digest as the key.

Swapin:

1. Resolve the swap device from the entry.
2. Acquire-load the table slot validity.
3. Return `-ENOENT` if no digest is stored.
4. GET the page using the stored digest as the key.

Slot release calls `rswap_hash_invalidate()` from `mm/swapfile.c`, clearing
table validity before the slot is reused. Device teardown frees the full
table.

The `valid` flag uses release/acquire ordering so a reader cannot observe a
valid slot before the digest contents are visible.

### Data Flow

```text
user mmap
  -> userspace SHA-256 per base page
  -> /proc/sys/vm/rswap/attach
  -> page_ext hash + valid
  -> reclaim / swapout
  -> device table[swp_offset] = page_ext hash
  -> HTTP POST /v1/folios/<hash>/write

swap fault
  -> device table[swp_offset]
  -> HTTP GET /v1/folios/<hash>/read
  -> page is filled and unmapped metadata may disappear
  -> swap slot release invalidates the table entry
```

## Relevant Files

- `mm/rswap.c`: rswap core, backend selection, sysctl, page-ext and table
  implementation.
- `mm/rswap_backend.h`: pluggable KV backend interface and transport API.
- `mm/rswap_sock.c`: TCP connect/send/receive helpers shared by backends.
- `mm/rswap_http.c`: HTTP/1.0 KV backend for `kvswap_server`.
- `mm/rswap_redis.c`: RESP KV backend for Redis.
- `mm/rswap.h`: rswap lifecycle declarations and no-op configuration stubs.
- `include/linux/page_ext.h`: page-ext client declarations and lifecycle hooks.
- `mm/page_ext.c`: page-ext client registration.
- `include/linux/swap.h`: per-device hash table pointer in
  `struct swap_info_struct`.
- `mm/page_alloc.c`: clear page-ext digest on page free.
- `mm/migrate.c`: copy page-ext digest on migration.
- `mm/swapfile.c`: xswap device creation/destruction and slot-release hash
  invalidation.
- `Documentation/admin-guide/sysctl/vm.rst`: sysctl ABI documentation.
- `rswap-userspace-demos/`: mmap, userspace hashing, and sysctl attach tool.
- `tools/mm/kvswap_server.c`: HTTP KV backend.
- `tools/mm/rswap_test.c`: bounded integrity verifier that attaches page
  hashes before reclaim.
- `tools/mm/rswap_run_test.py`: cgroup-based live test runner.
- `tools/mm/rswap_scale_test.py`: scaled live test (512 MiB by default) that
  also sets up the KV server and swap device, then audits the backend keys.
- `tools/mm/rswap_backend_test.py`: source-level backend and table regressions.
- `tools/mm/rswap_redis_test.py`: RESP client test against a scripted server,
  plus `--live` against a real Redis server.
- `tools/mm/kvswap_test.py`: HTTP protocol regression tests.

## Interfaces and Operations

Create an rswap device:

```sh
echo "rswap 200" > /sys/kernel/mm/xswap/create
```

Destroy it by swap type:

```sh
echo 0 > /sys/kernel/mm/xswap/destroy
```

The endpoint comes from the boot parameters; the defaults are
`127.0.0.1:6789` for the HTTP backend and `127.0.0.1:6379` for Redis.

Start the HTTP server:

```sh
tools/mm/kvswap_server -d /tmp/rswap-kv -p 6789
```

The server endpoints are:

```text
POST /v1/folios/<sha256>/write
GET  /v1/folios/<sha256>/read
```

Or boot with the Redis backend and point it at a server:

```text
rswap.backend=redis rswap.host=192.0.2.10 rswap.port=6379
rswap.redis_user=default rswap.redis_password=<secret> rswap.redis_db=0
```

Redis objects are the raw page images stored under the 64 hex digit digest,
so `GET <sha256>` on the server must return exactly one base page.

Selected backend information is exposed through debugfs:

```text
/sys/kernel/debug/rswap/backend             http | redis
/sys/kernel/debug/rswap/endpoint            resolved host:port
/sys/kernel/debug/rswap/type<N>/kv_port     resolved port of type <N>
```

## Build and Verification

Build the kernel and relevant objects:

```sh
make O=build LLVM=1 -j"$(nproc)" W=1 \
    mm/rswap.o mm/rswap_sock.o mm/rswap_http.o mm/rswap_redis.o \
    mm/swapfile.o mm/page_alloc.o mm/migrate.o Image
```

Build userspace tools:

```sh
make -C rswap-userspace-demos user
make -C tools/mm kvswap_server rswap_test
```

Build the installable kernel packages:

```sh
make O=build LLVM=1 -j"$(nproc)" binrpm-pkg
```

Source and protocol tests:

```sh
python3 tools/mm/rswap_backend_test.py
python3 tools/mm/kvswap_test.py
python3 tools/mm/rswap_redis_test.py
```

The Redis test builds a userspace harness from the real RESP code in
`mm/rswap_redis.c` and runs it against a scripted RESP server. With `--live`
it also runs against a real server and audits the stored objects:

```sh
python3 tools/mm/rswap_redis_test.py --live --host 127.0.0.1 --port 6379 \
    --user default --password "$RSWAP_REDIS_PASSWORD" --db 0
```

Live integrity test, with rswap as the only active swap device:

```sh
sudo python3 tools/mm/rswap_run_test.py --size-kib 8192 --rounds 5
```

Scaled live test (512 MiB of anonymous memory by default). It starts the KV
server, creates the rswap device, runs the verifier in a bounded cgroup, and
then checks that the backend holds exactly one full page object per base
page and nothing else. `--takeover-swap` swaps off existing devices for the
duration of the run and restores them before exit:

```sh
sudo python3 tools/mm/rswap_scale_test.py --takeover-swap
sudo python3 tools/mm/rswap_scale_test.py --size-kib 524288 --rounds 2 \
    --takeover-swap --huge
```

The verifier now attaches userspace hashes before each round. This update is
required because unattached pages intentionally fail writeout.

For manual live testing, stop zram swap before creating the remote-only
configuration (`rswap_scale_test.py --takeover-swap` does this and restores
it):

```sh
sudo swapoff /dev/zram0
echo "rswap 200" > /sys/kernel/mm/xswap/create
# Run tests.
echo 0 > /sys/kernel/mm/xswap/destroy
sudo systemctl start systemd-zram-setup@zram0.service
```

Always restore the original swap configuration and stop the KV server after
testing.

## Verified Behavior

The no-fallback design has been tested live on ARM64 with 16 KiB base pages:

- 512/512 attached pages for an 8 MiB userspace mapping.
- A two-page negative test with one attached digest produced exactly one
  backend key: the attached userspace digest. There was no entry-derived
  fallback key.
- A four-page forced-pageout test stored exactly four userspace digests and
  read all contents back correctly.
- An 8 MiB forced-pageout test stored all 512 expected keys, no extra keys,
  and read all 512 pages back byte-for-byte.
- `rswap_run_test.py` passed five rounds with 512/512 pages evicted and all
  8 MiB matching in every round.
- `rswap_scale_test.py` passed a 512 MiB run with 32768/32768 pages evicted,
  all 512 MiB matching, and exactly 32768 page-sized backend objects with no
  extras. A 64 MiB two-round run stored exactly 8192 objects.
- Backend source regressions and all 11 KV protocol tests passed.

After the backend split the live runs above still target the HTTP backend.
The Redis backend has been verified at the protocol level only, because that
requires a kernel with `CONFIG_RSWAP_KV_REDIS=y` booted:

- `rswap_redis_test.py` builds the real `mm/rswap_redis.c` RESP code against
  POSIX socket shims and passes against a scripted RESP server: pipelined
  AUTH/SELECT/SET, `GET` round trip, `$-1` mapped to `-ENOENT`, `-WRONGPASS`
  and `-NOAUTH` mapped to `-EACCES`, `SELECT <n>` honored, a non-page-sized
  object rejected with `-EMSGSIZE`, and exactly one key per user digest.
- `rswap_redis_test.py --live` passes against a real password-protected Redis
  server: the page is stored as one 4 KiB object under the userspace SHA-256
  hex key, reads back byte-for-byte, a missing key fails with `-ENOENT`, and
  the test leaves no objects behind.

With a kernel booted as `rswap.backend=redis` against a remote server, the
verifier attached digests before each round and the Redis database was audited
by recomputing the expected digests from the test seed:

- 8 MiB, 1 round: 512/512 pages evicted, all bytes matched, 512 objects, each
  exactly one 16 KiB page under the expected userspace digest, no extras.
- 16 MiB, 2 rounds: 1024/1024 pages evicted per round, 2048 distinct objects
  (no key reuse between rounds), all content-exact, no extras.

Batching and its effect (`RSWAP_BATCH_MAX` = 8, remote server, per page):

- `rswap_backend_test.py` checks the batching itself: an 8 page folio is one
  backend call, 12 pages split into 8 + 4, and data survives both directions.
- `rswap_redis_test.py` checks that a batch of 8 pages uses one connection and
  sends 8 pipelined `SET`/`GET` commands.
- Harness timing against the remote server: 8 pages one connection each cost
  42 ms/page written and 48 ms/page read; pipelined into one batch they cost
  7 ms/page in both directions.
- The live verifier used to spend ~60 ms per page operation; that is one TCP
  connect plus one RESP round trip to a proxied endpoint, not kernel time (the
  loopback HTTP backend does 0.09 ms per page operation).

Status of the refactor: `mm/rswap.c` no longer contains any socket, HTTP or
RESP code, and `rswap_backend_test.py` still passes unchanged in substance for
the response parser, the submit paths, the per-entry key path and slot
cleanup.

Expected `-ENODATA`/`-61` kernel messages occur during deliberate tests of
writeout without an attached digest. They are not evidence of a fallback
path.

## Known Limitations

- A page intended for remote swap must have a userspace digest attached
  before reclaim. If it does not, writeout fails and the page stays resident,
  which can eventually lead to OOM under pressure.
- The caller must update the digest after modifying page contents.
- The device table is in memory and is not persistent across swapoff,
  device destruction, or reboot. Remote server objects may remain.
- The current digest is an integrity input supplied by user space. The kernel
  does not independently recompute or verify it against page contents.
- The HTTP KV server has no authentication and the kernel sends no
  credentials to it. Redis supports `AUTH`/`SELECT`, but its secret is a boot
  parameter and is stored in plain text while the kernel runs.
- Throughput is bounded by round trips: one connection per batch, and the
  Redis backend still sends one command per page inside the batch. Both the
  single-threaded HTTP server and this design are for testing, not production
  throughput. A backend switch needs a reboot, and the backend for a device is
  never recorded, so a device written with one backend cannot be read back
  with another.
- `RSWAP_BATCH_MAX` also bounds the core's bounce buffer (8 base pages, 128 KiB
  with 16 KiB pages); raising it trades memory in the swap I/O path for fewer
  round trips.
- There is no active eBPF integration.

## eBPF Status

The eBPF prototype is postponed. `rswap-userspace-demos/page_hash_kern.bpf.c`
and `page_hash_test_mod.c` may remain as experimental source, but the active
Makefile builds only the userspace sysctl tool. Do not re-enable eBPF without
an explicit design change.

## Kernel Contribution Rules

Read and follow:

- `Documentation/process/coding-assistants.rst`
- `Documentation/process/generated-content.rst`
- `Documentation/process/coding-style.rst`
- `Documentation/process/submitting-patches.rst`
- `Documentation/process/submit-checklist.rst`

AI tools must not add `Signed-off-by` tags. The human submitter must review
the code, certify the DCO, and add their own sign-off.

Before finishing a change:

- run `git diff --check`;
- run `scripts/checkpatch.pl` on the changed code;
- compile all affected configurations, including `CONFIG_RSWAP=n` when
  generic MM hooks change;
- run the source-level, protocol, and live reclaim tests when the kernel can
  be installed;
- report tests that could not be run and any host state that was changed.
