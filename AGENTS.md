# Remote Swap (rswap) Agent Guide

This file applies to the whole repository. It records the rswap-specific
architecture, invariants, interfaces, test workflow, and kernel contribution
rules that future coding agents must preserve.

## Non-Negotiable Invariant

**Never calculate or derive an rswap page key from a swap entry in the
kernel.**

User space supplies the digest of every page it wants stored remotely. The
kernel must not run a hash function over `swp_entry_t`, the page contents, or
any other kernel-derived value to create a key.

The digest is an opaque 48-byte value (`RSWAP_HASH_LEN`, `mm/rswap.h`). The key
is that value rendered with `bin2hex()`: `RSWAP_HASH_HEXLEN` = 96 hex
characters in `RSWAP_KV_KEY_LEN` = 97 bytes including the NUL
(`mm/rswap_backend.h`, pinned by the `static_assert` in `mm/rswap.c`). Today's
digest program emits 32 bytes of SHA-256 and leaves the rest zero, and a digest
attached through `/proc/sys/vm/rswap/attach` is a 32-byte SHA-256 zero extended
to the slot width, but nothing in the key layout depends on that.

The key comes from one of two user-space interfaces, in this order:

1. A digest program attached to the VMA that maps the page
   (`/sys/kernel/mm/xswap/rswap_attach`). The kernel runs it at unmap time,
   while the page is still mapped, and stages the result in the digest slot of
   the page's swap cluster.
2. The legacy page_ext digest attached to the base page through
   `/proc/sys/vm/rswap/attach`, consulted on writeout only when the cluster
   slot holds no valid digest.

Writeout uses the slot digest, falls back to the page_ext digest, stores
whichever it used in the slot, and fails with `-ENODATA` when neither exists.
Do not add a fallback key. Swapin reads only the cluster slot and fails with
`-ENOENT` if it holds no valid digest.

An earlier implementation incorrectly hashed swap entries. That behavior was
removed in commit `e254942f9d5ac ("mm: rswap: use userspace provided hash
only")` and must not return.

## Project Purpose

rswap is a fileless xswap backend that stores swap pages in an external
key-value store. Each base page is stored under the 96 hex character key
rendered from the 48-byte digest user space supplied for that page.

The store is reached through a pluggable KV backend. The core (`mm/rswap.c`)
owns the keys, the per-cluster digest slots, the legacy page_ext digests and
the `swap_ops` wiring; a backend only moves one page image to and from the
store. Two backends ship with the kernel:

- `http` (`mm/rswap_http.c`): HTTP/1.0 `POST`/`GET` to a userspace
  `kvswap_server` that stores one file per key.
- `redis` (`mm/rswap_redis.c`): RESP `SET`/`GET` against a Redis server, using
  the same keys, so server contents can be audited against the userspace
  digests.

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
- A request is bounded in wall time, not just per socket operation.
  `rswap_sock_deadline()` turns a budget into an absolute deadline; each
  backend budgets connect, send and two receive timeouts for one request and
  the Redis budget also covers both attempts of the retry-once policy.
  `rswap_sock_send()`, `rswap_sock_send_bvecs()` and `rswap_sock_recv_page()`
  check it before each blocking operation and fail with `-ETIMEDOUT`. Both
  parsers read the header block in one receive into the remaining buffer space
  and rescan for the terminator instead of reading it a byte per syscall.
- Only genuine socket failures are retried: Redis `-EACCES`, `-ENOMEM` and
  `-EINVAL` are not transport errors. A pooled connection is dropped only when
  a reply of the batch is still outstanding, so a routine swapin `-ENOENT`
  does not cost a reconnect, and `connect()` has its own timeout so that a
  short send timeout cannot make a high-latency endpoint unconnectable.
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

Swapin is asynchronous, writeout is not. `swap_read_submit()` calls
`rswap_submit_read()`, which resolves every key and base page address in the
submitting task, prepares `sio->iocb`, hands each batch to the `rswap_read`
workqueue and returns; the caller's stack-allocated `struct swap_io_ctx` is
dropped there, and nothing dereferences `struct swap_info_struct` afterwards.
Writeout still calls `rswap_submit()` and waits for each
`rswap_flush_batch()`, because reclaim wants the folio writeback flag cleared
before it continues.

One work item is one `rswap_flush_batch()` call, so Redis still pipelines up
to 32 GET commands and HTTP still sends one object per request; the difference
is that batches of one request now overlap instead of being serialized.
`RSWAP_READ_MAX_ACTIVE` (8) is the read workqueue's `max_active`, i.e. the
number of batches a worker may move at once; the submitting task never waits
for one of those slots, so a single `MADV_WILLNEED` caller queues everything
its readahead produced and the workqueue decides how many remote round trips
overlap. max_active of a bound workqueue applies per CPU, so a submitter that
migrates can have more than eight batches running. The queue itself is not
bounded, and the batch bookkeeping is only `RSWAP_BATCH_MAX` keys plus one
`struct rswap_kv_page` per page: there is no bounce buffer, a page image
travels between the folio page and the socket, and the folios a batch names are
pinned by the swap request anyway. 8 matches `RSWAP_REDIS_POOL_MAX` and the
point where measured WILLNEED throughput stopped improving. When there is no
workqueue or it refuses the item, or the request structure cannot be
allocated, that batch is moved in the submitting task instead, i.e. the
previous synchronous behaviour, so swapin always makes forward progress under
memory pressure. `WQ_MEM_RECLAIM` keeps a worker runnable while reclaim waits
for it.

Completion is exactly once, through a `refcount_t` held once by the submitter
and once per dispatched batch: the last batch to finish calls
`sio->iocb.ki_complete(&sio->iocb, ret ? ret : sio->len)`, and the normal
`swap_read_end()` marks the folios uptodate, unlocks them and frees the
`swap_iocb`. The first negative errno fails the whole request, so a partial
success is never exposed as uptodate. All batches of a request share one
completion, and no batch touches the request after `ki_complete()`.

Teardown is fenced in `rswap_disable()`: it drains the read workqueue with
`flush_workqueue(rswap_read_wq)`. A batch never dereferences the device; it
carries the swap type and a referenced pointer to the device's counter block,
which the last `rswap_stats_put()` frees - the device drops only its own
reference there. The digest slots belong to the swap clusters and are released
with them. `__swapoff()` kills `si->users`, runs `synchronize_rcu()` and waits
for its holders before calling it, and runs without a lock held there, so the
drain cannot deadlock.

`read_avg_ns`/`read_max_ns` are measured around the backend call in the
worker, so they are real remote batch latency. `read_inflight` is the number of
batches a worker is moving right now and `read_peak_inflight` the largest
number that ever ran at once (a boot-lifetime maximum, reset when a device is
created); a batch waiting in the workqueue is not counted, because the queue is
not bounded. `read_fallbacks` counts batches moved in the submitting task
instead of a worker, and `read_submits` the read requests queued. The swapin
performance test separates `SUBMITTED` from `LOADED` for the same reason:
only `LOADED` means the remote reads finished.

### Read retry policy

A read batch is retried in `rswap_flush_batch()`; a write batch is not.

- Retried errno, i.e. failures a later attempt can plausibly survive:
  `-EINTR`, `-ETIMEDOUT`, `-ECONNRESET`, `-ECONNREFUSED`, `-ECONNABORTED`,
  `-EPIPE`, `-ENETUNREACH`, `-EHOSTUNREACH`, `-ENETDOWN`, `-EAGAIN`.
  `rswap_read_retryable()` is the only place that decides this.
- Not retried, because they answer for the request or the store rather than for
  this attempt: `-ENOENT`, `-ENODATA`, `-EIO`, `-EMSGSIZE`, `-EACCES`,
  `-ENOMEM`, `-EINVAL`, `-EPROTO`. Repeating them would only delay the fault
  that reports the real cause.
- `RSWAP_READ_MAX_RETRIES` (2) bounds a batch to three attempts, so a dead
  store costs three round trips of the same budget rather than a stall, and a
  fault that waits for the batch waits for all of them. Each retry costs one
  `cond_resched()` and one increment of `read_retries` in both the total and the
  device counter block; a first-attempt failure that is not retried does not
  increment it.
- A batch is idempotent, because a page store answers every read with the same
  object, so the whole batch is moved again and not just the pages an earlier
  attempt had not reached. Attempts are counted and timed as backend calls;
  pages and errors are accounted once, from the final outcome.
- Writeout is deliberately single attempt: reclaim keeps the folio resident and
  writes the page again itself, so a retry there would only lengthen the stall
  in the reclaim path.

The transport already retries a syscall interrupted by a signal (`-EINTR`)
inside the request budget, so this layer only sees failures that survived
that. `redis_retries` counts the backend's own retry on a fresh connection,
which is a separate, inner policy.

### Failed swapin

A swapin that fails after the retries is not fatal to the system and never
returns a zero page:

- `swap_read_end()` neither marks the folio uptodate nor keeps it locked, and
  `do_swap_page()` then fails its own `!folio_test_uptodate()` check with
  `VM_FAULT_SIGBUS` without installing a PTE. The accessing task gets `SIGBUS`;
  nothing else does.
- A repeated access finds the same folio in the swap cache and is not read
  again, so it fails the same way at no remote cost.
- Readahead only queues neighbours and drops its reference, so it never hands
  contents to a fault. Shmem fails with `-EIO` and poisons the entry; swapoff
  installs a poisoned entry.
- There is no folio error bit to set: `PG_error` was removed upstream, so the
  state `swap_read_end()` leaves *is* the failure marker.
- The failure is logged once per batch, rate limited, naming the swap type, the
  first offset of the batch, the page count and the key prefix, so the object
  can be found in the store.

### Endpoint and build scope

- The endpoint is a boot parameter; the defaults are `127.0.0.1:6789` (HTTP)
  and `127.0.0.1:6379` (Redis).
- No payload encryption and no persistence guarantees beyond the backend
  implementation. The HTTP server has no authentication at all; Redis uses
  `AUTH` and `SELECT` when a password resp. a database number is configured.
- The digest program (a `BPF_PROG_TYPE_SYSCALL` program) is shipped and part
  of the active build; see "Digest Program" below.

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

That sysctl is the legacy path: it attaches one digest to one base page and
the core uses it only when the page's cluster slot holds no digest from a
digest program. The shipped interface is the digest program, attached to the
VMA at `/sys/kernel/mm/xswap/rswap_attach`; both are documented in
`Documentation/ABI/testing/sysfs-kernel-mm-xswap-rswap` and
`Documentation/admin-guide/sysctl/vm.rst`. `rswap-userspace-demos/` still
builds only the userspace sysctl tool, so `page_hash_kern.bpf.c` and
`page_hash_test_mod.c` are demo sources the kernel does not depend on.

### Kernel Entry Point

`mm/rswap.c` is the core implementation. It contains:

- swap page I/O through the `swap_ops` interface;
- the `/proc/sys/vm/rswap/attach` sysctl and the page_ext digest it fills;
- the per-cluster digest slots and the hooks `mm/swapfile.c`, `mm/rmap.c` and
  `mm/shmem.c` call to fill, move and release them;
- the per-VMA digest program and `/sys/kernel/mm/xswap/rswap_attach`;
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
        const char      *key;   /* hex digest, RSWAP_KV_KEY_LEN bytes */
        struct page     *page;  /* exactly one base page image */
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

The store is chosen at boot, never at runtime: switching a live device to a
different store would strand every page already written to the old one. The
two timeouts do not decide where a page goes, so they are the exception and
stay tunable.

```text
rswap.backend=http|redis          default http
rswap.host=<address>              empty selects the backend default
rswap.port=<port>                 0 selects the backend default
rswap.redis_user=<acl user>       empty uses the Redis default user
rswap.redis_password=<secret>     empty sends no AUTH
rswap.redis_db=<n>                Redis database number
```

Those six are boot-only and `0444` in sysfs. The timeouts are boot parameters
and module parameters, writable at `/sys/module/rswap/parameters/`:

```text
rswap.send_timeout_ms=<ms>        0 selects the backend default, else 1..60000
rswap.recv_timeout_ms=<ms>        0 selects the backend default, else 1..60000
```

The unit of both parameters, of the backend defaults and of the deadline
budgets is milliseconds; on the socket they become jiffies.
`rswap_sock_connect()` converts each one with `msecs_to_jiffies()` and writes
`sk_rcvtimeo` and `sk_sndtimeo` directly, because `sock_set_sndtimeo()` takes
its argument in seconds and multiplies it by `HZ` (`net/core/sock.c`). The
defaults are 1000 ms connect, 1000 ms send and 1000 ms receive for HTTP, and
10000 ms for each of the three Redis timeouts. The HTTP send bound is 1 s
rather than something tight, because the first 128 KiB batch over a cold remote
path costs about 45 ms and a healthy endpoint must survive one slow send; what
actually bounds a request is the deadline (`rswap_http_deadline()`,
`rswap_redis_deadline()`), i.e. connect + send + 2 × receive, 4 s for HTTP and
40 s for Redis.

A write is validated and rejected with `-EINVAL` above 60000 ms, or when the
value does not parse. `rswap_http_deadline()` and `rswap_redis_deadline()`
call `rswap_kv_send_timeout()`/`rswap_kv_recv_timeout()` per request, so a
change applies to requests started afterwards: a batch already in flight keeps
the budget it computed at its start, and a pooled Redis connection keeps the
socket timeouts it was opened with until it is dropped. Zero means "the
backend default" at runtime too, so `echo 0` returns to it.

The secrets are boot parameters only; `rswap.redis_password` is deliberately
not exposed in sysfs and must not be committed to the tree.

The RSWAP Kconfig option is defined in `mm/Kconfig` and depends on:

- `XSWAP`
- `INET`
- `SYSCTL`

It selects `PAGE_EXTENSION` and `CRYPTO_LIB_SHA256`. `RSWAP_KV_HTTP`
(default y) and `RSWAP_KV_REDIS` (default n) build the individual backends;
at least one is required.

### Legacy Page-Ext Digest

A digest attached through `/proc/sys/vm/rswap/attach` lives in page_ext on the
base page:

```text
struct rswap_page_ext {
        u8 hash[SHA256_DIGEST_SIZE];
        bool valid;
};
```

The page-ext client is registered in `mm/page_ext.c`, declared in
`include/linux/page_ext.h`, and selected by `CONFIG_RSWAP`. Its `need`
callback returns true unconditionally, so its bytes per base page are reserved
whenever `CONFIG_RSWAP=y`, even if no rswap device is ever created (review
finding M6, deferred).

Access to the page digest is serialized by `rswap_hash_lock`, a global
spinlock for the short protected copy. Page-ext metadata is not assumed to
stay with one physical page forever:

- `rswap_page_ext_copy()` preserves the digest during folio migration.
- `rswap_page_ext_reset()` clears stale metadata when a page is freed.

`mm/migrate.c` invokes the copy hook. `mm/page_alloc.c` invokes the reset
hook on normal and hardware-poisoned page free paths.

Writeout is the only reader of this digest, and only when the cluster slot has
no valid digest; the value is then zero extended to the 48-byte slot width and
stored there. Swapin never looks at page_ext, because the page may have been
evicted and its page-ext data may no longer exist.

### Per-Cluster Digest Slots

The digest is resolved while the folio is still mapped, at unmap time, so the
slot lives with the swap clusters rather than with the device:

```text
struct rswap_hash {
        char data[RSWAP_HASH_LEN];
        u8 valid;
};

struct rswap_hash_table {
        struct rswap_hash *hashes[SWAPFILE_CLUSTER];
};
```

One table per swap cluster, reached through `swap_cluster_info`; slot `i`
describes swap offset `cluster_start + i`. There is no per-device
`kvcalloc(si->max, ...)` table. A NULL slot means "no slot reserved", and a
slot whose `valid` flag is clear means "no digest resolved".

Writeout:

1. Resolve each base page and its precise swap entry.
2. Acquire-load the cluster slot's `valid` byte; if it is set, use the digest.
3. Otherwise take the legacy page_ext digest; return `-ENODATA` if there is
   none either.
4. Publish the digest into the slot with release semantics.
5. Send the page using the digest as the key.

Swapin:

1. Resolve the swap device and cluster from the entry.
2. Acquire-load the slot's `valid` byte.
3. Return `-ENOENT` if no digest is stored.
4. Read the page using the stored digest as the key.

Filling the slot:

- `rswap_prepare_hashes()` reserves a slot for every base page of a folio that
  enters the swap cache (`folio_alloc_swap()`, `GFP_NOIO`, so it may sleep). A
  reserved slot is not valid: it reports "no digest" until one is stored.
- `rswap_attach_hash()` runs from `try_to_unmap_one()` right before the PTE is
  replaced by a swap entry. It runs the VMA's digest program and publishes the
  result into the slot.
- Shmem has no swap entry at unmap time, so `rswap_attach_hash_shmem()` stages
  the digest in the inode's xarray and `rswap_shmem_move_hashes()` moves the
  staged digests into the slots once the folio is in a cluster.

`rswap_hash_publish()` clears `valid`, copies the digest and then sets `valid`
with release semantics; readers acquire-load `valid` before touching the
bytes. That pairing means a reserved or released slot never reads back as an
all-zero digest.

Slot release calls `rswap_hash_invalidate()` from `mm/swapfile.c`, which
clears `valid` and keeps the object for the cluster's lifetime; the memory is
bounded at one slot per swap offset and is freed with the cluster by
`rswap_hash_table_free()`, so a lock-free lookup can never race a free.

### Data Flow

```text
user mmap
  -> userspace computes a digest per base page
  -> digest program attached to the VMA
     (/sys/kernel/mm/xswap/rswap_attach)
  -> unmap: try_to_unmap_one() -> rswap_attach_hash()
  -> cluster slot: data[48] + valid, store-release
  -> reclaim / swapout
  -> rswap_page_key(): slot digest, else page_ext digest, else -ENODATA
  -> bin2hex() -> 96 hex characters -> <key>
  -> POST /v1/folios/<key>/write   (or Redis SET <key>)

swap fault
  -> cluster slot of swp_offset(entry), acquire-load valid
  -> GET /v1/folios/<key>/read     (or Redis GET <key>)
  -> page is filled
  -> swap slot release: rswap_hash_invalidate() clears valid, keeps the slot
```

## Relevant Files

- `mm/rswap.c`: rswap core, digest slots, page-ext fallback, digest program,
  sysctl, backend selection.
- `mm/rswap_backend.h`: pluggable KV backend interface and transport API.
- `mm/rswap_sock.c`: TCP connect/send/receive helpers and the request deadline
  shared by backends.
- `mm/rswap_http.c`: HTTP/1.0 KV backend for `kvswap_server`.
- `mm/rswap_redis.c`: RESP KV backend for Redis.
- `mm/rswap.h`: digest slot layout, rswap lifecycle declarations, hook
  prototypes and no-op configuration stubs.
- `include/linux/mm_types.h`: `struct vm_area_struct::rswap_prog`.
- `include/linux/mm.h`: `VM_HASHED`.
- `include/linux/page_ext.h` / `mm/page_ext.c`: page-ext client declarations,
  lifecycle hooks and registration.
- `include/linux/swap.h`: `rswap_kv_port` and `rswap_stats` in
  `struct swap_info_struct`.
- `mm/swapfile.c`: xswap device creation/destruction, the
  `/sys/kernel/mm/xswap/rswap_attach` sysfs file, slot reservation and
  slot-release invalidation.
- `mm/rmap.c`: `try_to_unmap_one()`, which resolves the digest at unmap time.
- `mm/shmem.c`: shmem staging of digests until a swap entry exists.
- `mm/vma_init.c`: `rswap_vma_dup()`/`rswap_vma_free()` in the VMA copy and
  free paths.
- `mm/page_alloc.c`: clear the page-ext digest on page free.
- `mm/migrate.c`: copy the page-ext digest on migration.
- `Documentation/ABI/testing/sysfs-kernel-mm-xswap-rswap`: the sysfs attach
  ABI for the digest program.
- `Documentation/admin-guide/sysctl/vm.rst`: sysctl ABI documentation.
- `rswap-userspace-demos/`: mmap, userspace hashing, and sysctl attach tool.
- `tools/mm/kvswap_server.c`: HTTP KV backend.
- `tools/mm/rswap_test.c`: bounded integrity verifier that attaches page
  hashes before reclaim.
- `tools/mm/rswap_run_test.py`: cgroup-based live test runner.
- `tools/mm/rswap_scale_test.py`: scaled live test (512 MiB by default) that
  sets up a local HTTP KV server and swap device, then audits backend keys
  against the digest manifest; it is not a Redis setup/audit runner.
- `tools/mm/rswap_pageout_test.c` / `.py` / `.rst`: separate whole-mapping
  MADV_PAGEOUT test, trace runner, and usage notes; measures batch overlap,
  swap PTEs, and physical residency independently.
- `tools/mm/rswap_swapin_test.c` / `.py` / `.rst`: separate cold swapin
  benchmark comparing WILLNEED with page faults and multiple reader threads.
- `tools/mm/rswap_backend_test.py`: source-level regressions for the digest
  slot, the key path, batching, retry policy, counters and the response parser.
- `tools/mm/rswap_redis_test.py`: RESP client test against a scripted server,
  plus `--live` against a real Redis server.
- `tools/mm/kvswap_test.py`: HTTP protocol regression tests.
- `TODOS.md`: asynchronous `submit_read` design, validation results and the
  follow-ups it did not cover.

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
POST /v1/folios/<key>/write
GET  /v1/folios/<key>/read
```

`<key>` is the 96 hex character digest, i.e. `RSWAP_HASH_HEXLEN` characters;
`kvswap_server` rejects any other width with 400.

Or boot with the Redis backend and point it at a server:

```text
rswap.backend=redis rswap.host=192.0.2.10 rswap.port=6379
rswap.redis_user=default rswap.redis_password=<secret> rswap.redis_db=0
```

Redis objects are the raw page images stored under the same 96 hex character
key, so `GET <key>` on the server must return exactly one base page.

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

Swapin additionally reports its queue and submission cost:

```text
read_inflight          1
read_peak_inflight     8
read_fallbacks         0
read_submits           1024
read_submit_avg_ns     210000
```

`read_inflight` is the number of read batches a worker is moving, i.e. of
remote round trips in progress, `read_peak_inflight` the largest value it
reached since the device was created, `read_fallbacks` batches that had to be
moved in the submitting task (no workqueue or a refused work item),
`read_submits` read requests queued and `read_submit_avg_ns` the average time a
submission spent before returning to the caller. A batch waiting in the
workqueue is not counted in `read_inflight`: the queue is not bounded, so its
depth would not say anything about overlap. `read_retries` counts read batches
moved again after a transient transport failure (see "Read retry policy"); it
is printed with the page counters, between `read_no_entry` and `read_avg_ns`.
A request that finds no memory for its queue bookkeeping at all runs the
previous synchronous path inside `rswap_submit()` instead and shows up only in
`read_pages`/`read_batches`. `read_batches` and `read_avg_ns` still count
and time the backend calls themselves, now from the worker.

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
time is excluded. Because swapin is asynchronous, the test reports two
instants: `SUBMITTED`, when the WILLNEED calls and the page-fault loads
returned, and `LOADED`, when `mincore()` finds every page resident again
(which for a swap-cache folio only happens after the remote read completed).
The load-time and bandwidth numbers use `LOADED`; the difference between the
two is the completion tail. Report batch latency as backend-call latency, not
bare RTT or individual page-fault latency. Under concurrency, compute
bandwidth from wall time rather than summed overlapping batch durations.

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

The no-fallback design has been tested live on ARM64 with 16 KiB base pages.
The live results in this section predate the 48-byte digest and the 96 hex
character key: they were recorded with the 64 hex digit SHA-256 key of that
time. Their page and byte counts, eviction checks and content audits still
hold; only the key width they quote is the old one.

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
  the test leaves no objects behind. (64 hex digits at the time; that digest
  is now the low half of a 96 hex character key.)

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
capacity. Those findings motivated the asynchronous `submit_read` path, which
turns one WILLNEED caller into up to `RSWAP_READ_MAX_ACTIVE` overlapping
batches; the numbers in this table predate it and were measured with a
synchronous backend.

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

- A page intended for remote swap must have a digest before reclaim: either a
  digest program on its VMA or the legacy page_ext attach. Otherwise writeout
  fails with `-ENODATA` and the page stays resident, which can eventually lead
  to OOM under pressure.
- The digest is resolved once, at unmap time, and the caller owns its
  correctness. The kernel does not recompute or verify it against the page
  contents, and it does not notice that the contents changed after the digest
  was resolved.
- Shmem digests are staged in the inode and moved into the cluster when the
  folio reaches the swap cache; a shmem page is therefore keyed by the digest
  resolved at its last unmap, not by any later modification.
- The per-cluster slots are in memory and are not persistent across swapoff,
  device destruction or reboot, and the swap slot release clears their
  validity, so a released slot never reuses its digest. Remote server objects
  may remain.
- The HTTP KV server has no authentication and the kernel sends no
  credentials to it. Redis supports `AUTH`/`SELECT`, but its secret is a boot
  parameter and is stored in plain text while the kernel runs.
- Swapin batches overlap, but at most `RSWAP_READ_MAX_ACTIVE` (8) are moved at
  once, because that is the read workqueue's `max_active`, so a single caller
  of `MADV_WILLNEED` reaches at most the throughput of eight concurrent round
  trips on one CPU. The depth is a compile-time constant, and the HTTP backend
  still opens one connection per object. Both the single-threaded HTTP server
  and this depth are for testing, not production throughput. A backend switch
  needs a reboot, and the backend for a device is never recorded, so a device
  written with one backend cannot be read back with another.
- Read throughput is bounded by the batch size and the workqueue's
  `max_active`, both compile-time constants: a live run reached ~22 MB/s, i.e.
  roughly eight minutes for a 32k-token DeepSeek prefill (~10 GiB) to spill, at
  22.8 ms per 32-page batch. The Redis connection pool semaphore is shared with
  writeout, so a saturated read queue delays reclaim-context writeout by one
  remote batch. Raising either number is a measurement exercise, not a bug fix;
  it costs transient memory per queued batch.
- A transient failure of a read batch is retried twice per batch and then
  reported, so a store that stays down costs three round trips (three request
  budgets) per batch before the fault. Reclaim retries the page instead:
  writeout is never retried by the core, because `-ENODATA`/`-EIO` there just
  leaves the folio resident for the next reclaim pass.
- A batch holds only bookkeeping: `RSWAP_BATCH_MAX` keys of `RSWAP_KV_KEY_LEN`
  bytes plus one `struct rswap_kv_page` per page, so a few KiB per batch and
  one pinned folio per page. Neither backend copies a page image: the bytes
  travel between the folio page and the socket as a `struct bio_vec`, so the
  transient cost of a batch is its folios, not a bounce buffer.
- The digest program runs under the page table lock, from
  `try_to_unmap_one()`, so it must not sleep and must not fault. It cannot
  take locks that reclaim or the page table lock holder may already hold.
- `VM_HASHED` and `rswap_prog` live on the VMA. `rswap_vma_dup()` drops both
  on every VMA copy, so `fork` does not inherit a digest program and a range
  split by `mprotect()` or `mremap()` stops resolving digests; such pages fall
  back to the legacy page_ext digest and otherwise fail writeout.
- The kernel preallocates the page-ext client while `CONFIG_RSWAP=y`, so its
  bytes per base page are reserved even when no rswap device exists (review
  finding M6, deferred).

## Digest Program

The digest program is shipped and part of the active build.

What it provides:

- `struct vm_area_struct::rswap_prog` (`include/linux/mm_types.h`) and
  `VM_HASHED` (`include/linux/mm.h`) mark a VMA whose pages must be hashed.
- `/sys/kernel/mm/xswap/rswap_attach` (`mm/swapfile.c`) attaches a program fd
  to the VMA that holds a given address in the writing task, or detaches it
  with a zero fd. It requires `CAP_SYS_ADMIN`. The ABI is documented in
  `Documentation/ABI/testing/sysfs-kernel-mm-xswap-rswap`.
- The program type is `BPF_PROG_TYPE_SYSCALL`, so it may write to its context
  (`struct rswap_hash_ctx`: the page's virtual address and the 48-byte digest
  buffer) and signal success through its return value.
- `rswap_attach_hash()` runs it from `try_to_unmap_one()` for anonymous folios,
  `rswap_attach_hash_shmem()` stages the reply for shmem, and the result is
  published into the cluster digest slot.
- The program pointer is read with `rcu_dereference()` inside an RCU read-side
  section, writers publish with `rcu_replace_pointer()`, and `bpf_prog_put()`
  defers the free through a grace period, so attach and detach are safe against
  a concurrent unmap.

What it does not provide:

- It cannot sleep or fault: it is called under the page table lock, in the
  middle of unmapping, so no blocking operation, no userspace access and no
  allocation that may reclaim.
- It does not fix the digest to the contents: it is asked once, at unmap time,
  and the caller is responsible for what it returns.
- It does not survive a VMA copy. `rswap_vma_dup()` clears the flag and the
  program, so `fork` and VMA splits lose it.
- The userspace demos do not build a program: `make -C rswap-userspace-demos
  user` builds only `page_hash_user`, the legacy sysctl tool, while
  `page_hash_kern.bpf.c` and `page_hash_test_mod.c` are demo sources the kernel
  does not depend on.

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
