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

- The core hands a backend up to `RSWAP_BATCH_MAX` (32) pages at a time, which
  the Redis backend pipelines into a single write; HTTP/1.0 carries one object
  per request and turns a batch into a sequence of requests.
- The Redis backend pools connections (`RSWAP_REDIS_POOL_MAX` = 8) and reuses
  them, with `AUTH`/`SELECT` sent once per connection. A fresh connection per
  batch costs ~90 ms for 128 KiB against ~15 ms on an established one (TCP
  handshake plus slow start over the remote path). A pooled socket whose peer
  has closed is detected and dropped, and a batch that fails on the transport
  is retried once on a fresh connection, which is safe because `SET`/`GET` are
  idempotent. HTTP opens a connection per request as before.
- `->can_merge()` accepts merging so several folios (up to the swap core's
  `SWAP_CLUSTER_MAX` bvecs) share one request; that is what fills a batch on
  the base-page path, where every folio is a single 4 KiB/16 KiB page.

### Request granularity

How full a batch gets is decided by two core paths, not by the backend:

- `->can_merge()`: without it the swap core submits one folio per request, so
  every 4 KiB/16 KiB base page costs its own round trip. rswap merges when
  every page of both folios can move.
- swap readahead: plain xswap skips it because its entries live only in zswap,
  but rswap entries live in the remote store, so `mm/swap_state.c` keeps
  readahead for `SWP_RSWAP`. One fault's readahead window becomes one request.

A fault that finds no readahead window still submits one page
(`swapin_sync`), and the HTTP backend always sends one object per request.

### Submission and completion

The current rswap submission path is synchronous, even when reached through
`read_swap_cache_async()` or `MADV_WILLNEED`. `swap_read_submit()` calls
`rswap_submit_read()` directly; `rswap_submit()` waits for each
`rswap_flush_batch()` before advancing. Redis pipelines up to 32 GET commands,
then receives all responses in that batch before the next batch is sent.
Pooling reuses connections and permits overlap between callers; a single
caller still has only one batch in flight. WILLNEED fills larger batches but
does not make this backend asynchronous.

The planned optimization is recorded in `TODOS.md`: dispatch/queue reads and
return promptly, allow bounded concurrent I/O, and invoke the existing swap
completion callback when each request finishes. Preserve request, folio,
buffer and device lifetimes, complete exactly once, and drain outstanding
work safely during teardown. This is pending work, not implemented behavior.
The swapin performance test must then separate submission time from actual
I/O completion instead of assuming WILLNEED has finished loading on return.

### Endpoint and build scope

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
request fails, which is why `rswap_can_merge()` only merges folios whose pages
all have a digest: a page that cannot be moved must fail alone instead of
taking its request neighbours down with it.

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
  sets up a local HTTP KV server and swap device, then audits backend keys;
  it is not a Redis setup/audit runner.
- `tools/mm/rswap_pageout_test.c` / `.py` / `.rst`: separate whole-mapping
  MADV_PAGEOUT test, trace runner, and usage notes; measures batch overlap,
  swap PTEs, and physical residency independently.
- `tools/mm/rswap_swapin_test.c` / `.py` / `.rst`: separate cold swapin
  benchmark comparing WILLNEED with page faults and multiple reader threads.
- `tools/mm/rswap_backend_test.py`: source-level backend, batching, counter and
  table regressions.
- `tools/mm/rswap_redis_test.py`: RESP client test against a scripted server,
  plus `--live` against a real Redis server.
- `tools/mm/kvswap_test.py`: HTTP protocol regression tests.
- `TODOS.md`: pending asynchronous `submit_read` design, lifecycle requirements,
  and validation criteria.

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

Selected backend information and the I/O counters are exposed through
debugfs:

```text
/sys/kernel/debug/rswap/backend             http | redis
/sys/kernel/debug/rswap/endpoint            resolved host:port
/sys/kernel/debug/rswap/stats               backend-wide counters
/sys/kernel/debug/rswap/type<N>/kv_port     resolved port of type <N>
/sys/kernel/debug/rswap/type<N>/stats       counters of type <N>
```

`stats` reports, per direction, the pages and bytes moved, the number of
backend batches, the failed pages, and for writeout the pages that had no
attached digest (`written_no_digest`) resp. for swapin the entries with no
stored digest (`read_no_entry`). Failed pages count attempts: reclaim retries
a page it could not move, so one such page is counted more than once. Such a
failure happens before the backend is called, so it costs no round trip.

Backends may add their own lines at the end of `stats`; the Redis backend
reports its connection pool:

```text
redis_connects      1
redis_reuses        258
redis_dropped       0
redis_retries       0
```

`redis_connects` counts sockets opened, `redis_reuses` batches that found a
live pooled socket, `redis_dropped` stale or broken sockets closed, and
`redis_retries` batches retried on a fresh connection. A steady state run
wants `reuses` to dominate and `connects` to stay small. It also reports the
average and peak batch time in nanoseconds, so
`written_avg_ns / (written_pages / written_batches)`
is the per-page store cost. Historical example with the old 8-page limit
(the current `batch_max` is 32):

```text
backend             redis
endpoint            21.6.122.137:6379
batch_max           8
written_pages       8192
written_bytes       134217728
written_batches     1024
written_errors      0
written_no_digest   0
written_avg_ns      57000000
written_max_ns      120000000
read_pages          ...
```

`type<N>/stats` shows the same page and failure counters for one device. The
counters are lock-free (`atomic64_t`) and only incremented in the swap I/O
path; a debugfs read races with them harmlessly.

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
make -C tools/mm kvswap_server rswap_test rswap_pageout_test rswap_swapin_test
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

Scaled live HTTP test (512 MiB of anonymous memory by default). It starts the
local KV server, creates the rswap device, runs the verifier in a bounded
cgroup, and then checks that the backend holds exactly one full page object per base
page and nothing else. `--takeover-swap` swaps off existing devices for the
duration of the run and restores them before exit:

```sh
sudo python3 tools/mm/rswap_scale_test.py --takeover-swap
sudo python3 tools/mm/rswap_scale_test.py --size-kib 524288 --rounds 2 \
    --takeover-swap --huge
```

The verifier now attaches userspace hashes before each round. This update is
required because unattached pages intentionally fail writeout.

### Whole-mapping pageout and cold swapin performance

Keep these experiments in their separate test files; do not repurpose the
existing `rswap_test.c` / `rswap_run_test.py` integrity test in place.
Both new runners default to 512 MiB and require the configured backend to be
reachable, debugfs/tracefs mounted, and `CONFIG_FPROBE_EVENTS`. They create
private trace instances to measure batch size and overlapping entry/return
intervals. Stop other rswap workloads while measuring global counters.

```sh
sudo python3 tools/mm/rswap_pageout_test.py --takeover-swap \
    --output /tmp/rswap-pageout-base
sudo python3 tools/mm/rswap_pageout_test.py --takeover-swap --huge \
    --output /tmp/rswap-pageout-thp
sudo python3 tools/mm/rswap_swapin_test.py --takeover-swap \
    --mode willneed --workers 1 --output /tmp/rswap-willneed-1
sudo python3 tools/mm/rswap_swapin_test.py --takeover-swap \
    --mode willneed --workers 8 --output /tmp/rswap-willneed-8
sudo python3 tools/mm/rswap_swapin_test.py --takeover-swap \
    --mode fault --workers 8 --output /tmp/rswap-fault-8
```

Output directories must be new. `--size-kib` allows smaller checks. Swapin
accepts 1..32 workers dividing the page count, each on a disjoint range.
The runners restore swap configuration and remove their cgroup and tracing
state. They retain `result.json`, raw traces, logs and `digests.txt`; backend
objects remain for a separate audit/cleanup using that manifest. Preserve
preexisting backend objects. Neither runner starts a backend server.

The pageout test issues exactly one MADV_PAGEOUT over the entire mapping,
without retries or `memory.reclaim`. Successful backend writes and swap PTEs
do not prove RAM was freed: `mincore()` can still find pages in swap cache.
The swapin test therefore follows pageout with bounded cgroup reclaim and
requires every page nonresident before timing. It checks actual remote byte
counts, then verifies every word with no additional remote reads. Preparation
time is excluded. Report batch latency as backend-call latency, not bare RTT
or individual page-fault latency. Under concurrency, compute bandwidth from
wall time rather than summed overlapping batch durations.

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
Redis protocol checks also passed; the subsequent live results below use a
kernel booted with `CONFIG_RSWAP_KV_REDIS=y`:

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

Earlier batching measurements and regressions (remote server; the initial
batch limit was 8 and was subsequently raised to 32):

- Live, 16 MiB x 2 rounds with `can_merge()` disabled: `written_pages` 2048
  but `written_batches` 2048 (one page per request) and 4m25s wall time. With
  merging: 258 batches (7.9 pages per batch), 2m27s, `read_batches` still 2048
  because swapin readahead was skipped for xswap. Both runs audited exactly
  2048 objects, no extras, content-exact.

- At the current 32-page limit, `rswap_backend_test.py` checks that 8- and
  12-page folios each use one backend call, 40 pages split into 32 + 8, and
  data survives both directions.
- `rswap_redis_test.py` checks that 32 pages use one connection with 32
  pipelined `SET`/`GET` commands, plus reuse across successive batches.
- Harness timing against the remote server: 8 pages one connection each cost
  42 ms/page written and 48 ms/page read; pipelined into one batch they cost
  7 ms/page in both directions.
- Measured per batch against the remote server: a fresh connection needs 2 ms
  to connect, ~34 ms for the first command, and 45-54 ms for the first 128 KiB
  batch (TCP slow start), settling at 13-15 ms per batch once warm. So the
  connection, not the batch size, was the bottleneck; pooling it takes a batch
  from 71 ms to 25 ms in the harness (15 ms steady state).
- With a warm pooled connection the batch size then pays: 8 pages per batch
  cost 15.9 ms (2.0 ms/page), 16 pages 17.6 ms (1.1 ms/page) and 32 pages
  22.3 ms (0.7 ms/page), against a ~12 ms path round trip. That is why
  `RSWAP_BATCH_MAX` is 32: one round trip per 512 KiB.
- The live verifier used to spend ~60 ms per page operation; that is one TCP
  connect plus one RESP round trip to a proxied endpoint, not kernel time (the
  loopback HTTP backend does 0.09 ms per page operation).
- `rswap_backend_test.py` also runs the real counter helpers: pages, batches
  and failed pages are accounted once per page in both the total and the
  per-device struct, only `-ENODATA`/`-ENOENT` count as `no_digest`/`no_entry`,
  and peak plus accumulated batch time are checked separately.

Status of the refactor: `mm/rswap.c` no longer contains any socket, HTTP or
RESP code, and `rswap_backend_test.py` still passes unchanged in substance for
the response parser, the submit paths, the per-entry key path and slot
cleanup.

### November 2, 2026: 32-page batching and concurrency

Tested on kernel `aeb11a14094d`, ARM64 with 16 KiB pages and remote Redis:

- Integrity/reclaim runs passed at 8 MiB x 5 rounds, 16 MiB x 2 rounds, and
  512 MiB with base pages and THP. Every page was evicted, every byte matched,
  and all 72,192 objects across these runs and a readahead check passed exact
  digest/content audits. One Redis connection served 11,116 batches without
  drops or retries. Backend harnesses, all 11 HTTP protocol tests, scripted
  and live Redis tests, and the affected rswap object build with `W=1` passed.
- One 512 MiB MADV_PAGEOUT: base pages took 25.58 s (20.01 MiB/s), with
  1,025 batches; THP took 29.16 s with 1,024 full 32-page batches. Both traces
  showed one writer and peak concurrency one. All 32,768 pages were written
  and became swap PTEs, but only 1,023/1,024 pages (about 16 MiB) were
  nonresident immediately. The rest remained in swap cache. Full content
  verification and separate audits of all remote objects passed.

Cold swapin results below kept `vm.page-cluster=3`. Every run started with
32,768 nonresident pages, read exactly 512 MiB remotely without errors or
retries, and verified all contents with no further remote reads:

| Access mode | Callers | Load time | Payload MiB/s | Peak active batches |
|---|---:|---:|---:|---:|
| Page faults | 1 | 61.42 s | 8.34 | 1 |
| WILLNEED | 1 | 52.72 s | 9.71 | 1 |
| WILLNEED | 2 | 36.59 s | 13.99 | 2 |
| WILLNEED | 4 | 23.67 s | 21.63 | 4 |
| WILLNEED | 8 | 22.76 s | 22.50 | 8 |
| Page faults | 8 | 24.79 s | 20.66 | 8 |

WILLNEED used 1,024 full 32-page batches in each run. Page faults averaged
about eight pages per batch. WILLNEED batch p50/p95 latency increased from
48.70/67.96 ms with one caller to 148.24/300.49 ms with eight, while total
load time fell because requests overlapped. Throughput flattened around
four to eight callers; individual runs do not establish physical link
capacity. These findings motivate the asynchronous `submit_read` TODO.

The cold tests recorded a 2,129,920-byte cgroup swap charge after verifier
exit, before device teardown; its cause was not established and it is not
proof of unfinished remote reads. The measured mapping was fully loaded
and verified. Swap configuration and tracing were restored; each run's
exact key set and object sizes were audited and test objects removed.

Expected `-ENODATA`/`-61` messages can occur when deliberate negative tests or
cgroup reclaim attempt unattached pages outside the test mapping. Compare
`written_errors` with `written_no_digest` and audit keys; these rejects alone
are not backend transport failures or evidence of a fallback path.

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
- One caller waits for each batch to finish before submitting the next,
  including on WILLNEED. Redis leases and reuses a pooled connection for each
  batch and sends one command per page; overlapping callers can use multiple
  connections. Asynchronous read submission is pending in `TODOS.md`. Both
  the single-threaded HTTP server and this design are for testing, not
  production throughput. A backend switch needs a reboot, and the backend
  for a device is never recorded, so a device written with one backend cannot
  be read back with another.
- `RSWAP_BATCH_MAX` also bounds the core's per-request batch buffer (32 base
  pages: 128 KiB with 4 KiB pages, 512 KiB with 16 KiB pages), kvmalloc'ed for
  the duration of a request, plus the same amount again in the Redis request
  buffer. That memory buys fewer round trips; with several CPUs in the swap I/O
  path at once the transient cost is a few MiB.
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
