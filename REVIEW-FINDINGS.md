# rswap review findings

Review of the rswap implementation at `62bda812a00f` ("mm: rswap: fix shmem")
on 2026-11-06. Four read-only reviewers covered disjoint seams — core swap
path, KV backends and transport, generic MM integration, and tools/tests/docs —
and the top findings were re-verified against the tree by hand.

Scope note: this tree has moved past what `AGENTS.md` describes. The digest is
48 bytes (`RSWAP_HASH_LEN`, `include/linux/swap.h` neighbour `mm/rswap.h:49`),
resolved by a per-VMA BPF program at unmap time and cached in a per-cluster
pointer table; keys are 96 hex characters (`mm/rswap.c:77`), not the documented
32-byte SHA-256 in a flat per-device `kvcalloc()` table. Findings below follow
the code.

Status legend: `open`, `fixed` (commit listed), `deferred` (accepted, not in
this pass), `invalid` (raised by the review, disproved against the tree).

## BLOCKER

### B1 — Unattached pages are written under the all-zero key

`open`.

`rswap_prepare_hashes()` reserves a digest slot for every folio entering the
swap cache (`mm/swapfile.c:2146`). The reservation allocates a zeroed object
(`kzalloc_obj()` + `cmpxchg` publish, `mm/rswap.c:478-490`), and
`rswap_hash_load()` (`mm/rswap.c:507-515`) reports success for it because
validity is the pointer value alone (`mm/rswap.h:66-71`, "a NULL slot means no
hash resolved"). The real digest is only stored later, and only for VMAs that
carry a digest program (`mm/rmap.c:2178-2179`).

Therefore the `-ENODATA` writeout path (`mm/rswap.c:826-830`) is unreachable
for such pages and `rswap_page_key()` emits 96 hex zeros
(`mm/rswap.c:839-840`) as the KV key:

- every page without a digest program collapses onto one remote object, and
  swapin returns whichever page was written last — silent data corruption;
- the non-negotiable invariant ("if no digest is attached, writeout fails with
  `-ENODATA`") does not hold, and `written_no_digest` never increments;
- the legacy `page_ext` digest from `/proc/sys/vm/rswap/attach` is ignored
  whenever the slot allocation succeeded, i.e. the key source depends on
  allocator luck;
- `rswap_folio_ready()` (`mm/rswap.c:1341-1354`) treats those pages as ready,
  so `can_merge()` offers no protection for them.

Fix: make slot validity explicit (`u8 valid` in `struct rswap_hash`, honoured
by `rswap_hash_load()`, published with release semantics after the digest
bytes) and never publish a usable slot before a digest exists.

### B2 — `xa_store()` error path frees the live xarray entry

`open`. `mm/rswap.c:727-729`:

```c
old = xa_store(&info->rswap_hashes, index, slot, GFP_NOWAIT);
if (xa_is_err(old) || old)
        kfree(slot);
```

`xa_store()` stores `slot` and returns the previous entry. When an entry
already exists the xarray now points at the just-freed `slot` and the old
object is leaked. Every later `xa_erase()` in `rswap_shmem_move_hashes()`
(`mm/rswap.c:763`) or `rswap_shmem_drop_hashes()` (`mm/rswap.c:786`) returns
the dangling pointer and either `memcpy()`s from it (`:770`) or frees it again
(`:771`, `:787`) — slab corruption.

Reachable because the hook runs per (folio, vma) in `try_to_unmap_one()`
(`mm/rmap.c:2256-2259`) and only skips folios already in the swap cache
(`mm/rswap.c:707-708`), so a folio mapped in two hashed VMAs re-stores the same
index.

### B3 — Every swap-slot release leaks a digest slot object

`open`. `rswap_hash_invalidate()` (`mm/rswap.c:1519`) publishes `NULL` over the
slot pointer and drops the only reference to the 48-byte object allocated in
`rswap_slot_get()` (`mm/rswap.c:482`). No other path frees it:
`rswap_hash_table_free()` (`mm/rswap.c:657-667`) only walks slots that are
still reachable. `swap_range_free()` (`mm/swapfile.c:1645-1651`) runs on the
normal free path of every swap entry, so the leak grows by one object per
reclaimed page and is invisible to the counters.

A plain `kfree()` here is not an option: lookups are lock-free
(`rswap_slot_lookup()` loads the pointer and `memcpy()`s from it,
`mm/rswap.c:443,515`). Fix together with B1: keep the slot for the cluster's
lifetime and clear the `valid` flag, which bounds the memory at
`sizeof(struct rswap_hash)` per slot and removes the leak.

### B4 — `mm/rswap_http.c` does not compile against the backend interface

`open`. `struct rswap_kv_page` is `{ const char *key; struct page *page; }`
(`mm/rswap_backend.h:38-41`) and the core fills `->page` (`mm/rswap.c:955`),
but the HTTP backend still dereferences the removed `->data` member at
`mm/rswap_http.c:207` and `:232`. `CONFIG_RSWAP_KV_HTTP` is `default y`
(`mm/Kconfig:167-169`), so a default rswap build breaks; the current
`build/.config` has the backend disabled, which is why this is invisible today.

### B5 — `kvswap_server` rejects every key the kernel sends

`open`. The kernel emits `2 * RSWAP_HASH_LEN` = 96 hex characters
(`mm/rswap.h:49`, `mm/rswap.c:77,839-840`, pinned by the `static_assert` at
`mm/rswap.c:81`), while `tools/mm/kvswap_server.c:54,218` accepts exactly 64.
Every POST/GET is answered with 400, which the backend maps to `-EIO`
(`mm/rswap_http.c:170`), so even after B4 the HTTP path cannot move a page.
`tools/mm/kvswap_test.py` only uses 64-character keys, so no test crosses the
seam.

Decision for this pass: 96 hex characters is the contract (a program-supplied
digest, not necessarily SHA-256), so widen the server and its tests and correct
the contradictory comments.

### B6 — Both source-level regression suites are stale

`open`. `tools/mm/rswap_backend_test.py:114-117` shims the removed
`struct rswap_kv_page { … void *data; }`, never defines `RSWAP_HASH_HEXLEN`
(used by the extracted `mm/rswap.c:840`), pins `RSWAP_KV_KEY_LEN 65` against the
real `97` (`mm/rswap_backend.h:24`), and sizes `expected_hex[]` at
`RSWAP_SHA256_HEXLEN + 1`, which a 97-byte key would overflow.
`tools/mm/rswap_redis_test.py` lacks the `bio_vec`, `bvec_set_page()`,
`mempool` and `folio_alloc()` shims the real backend body needs and also uses
`void *data`. Both build with `-Werror`, so they fail before running a case,
and nothing currently guards the invariants in AGENTS.md.

## MAJOR

### M1 — A read batch can be queued after the `rswap_disable()` drain

`open`. `rswap_disable()` (`mm/rswap.c:1559-1577`) frees `si->rswap_stats`
after `flush_workqueue()`, assuming no submission can still be in flight. That
does not hold for `MADV_WILLNEED`: `read_swap_cache_async()` drops the device
pin before the caller runs `swap_read_submit(&ctx)` (`mm/madvise.c:224-232`),
so a preempted submitter can pass `percpu_ref_kill()`, `synchronize_rcu()` and
the drain. The stats helpers early-return on `!stats` (`mm/rswap.c:247-278`),
so the common outcome is lost counters rather than a NULL dereference, but the
window is real.

Fix (rswap-local): take the per-device stats pointer into `struct rswap_batch`
at submit time from a stable owner, and stop freeing it in `rswap_disable()`.

### M2 — `vma->rswap_prog` lifetime is unprotected

`open`. `rswap_hash_lookup()` (`mm/rswap.c:533-546`) loads the pointer and
calls `bpf_prog_run()` with no reference, while `rswap_attach_prog()`
(`mm/rswap.c:630-651`) replaces it under `mmap_write_lock()` and
`bpf_prog_put()`s the old program after unlocking. The lookup runs from
`try_to_unmap_one()` under pte and rmap locks, which `mmap_write_lock()` does
not exclude and which is not an RCU read-side section, so the deferred free in
`bpf_prog_put()` can complete under a preempted lookuper.

Fix: `rcu_read_lock()` + `rcu_dereference()` around the lookup and
`kfree_rcu()`-style deferral for the detach.

### M3 — Per-request wall time is unbounded (one-byte reads)

`open`. Both parsers read headers a byte per syscall, and `sk_rcvtimeo` is
per syscall: HTTP up to 2047 calls at `recv_timeout_ms` (default 1000 ms,
`mm/rswap_http.c:137-147`, `mm/rswap_sock.c:54`), Redis up to 256 calls at
`RSWAP_REDIS_RECV_TIMEOUT_MS` (default 10 s, `mm/rswap_redis.c:209-229`). A
slow peer pins a read worker, its locked folios and an inflight slot for
minutes, and reclaim-context writeout queues behind it.

### M4 — Upstream `SWP_SYNCHRONOUS_IO` readahead suppression is gone (invalid)

`invalid`. Not a defect. The report was that upstream suppressed readahead for
synchronous devices in `mm/swap_state.c` and that the rswap change removed that
test. No upstream tree ever had such a test: `SWP_SYNCHRONOUS_IO` occurs zero
times in `mm/swap_state.c` in v6.0, v6.6, v6.12, v6.15 and v7.0, and
`git log --all -S SWP_SYNCHRONOUS_IO -- mm/swap_state.c` is empty. The line the
rswap change refines is the xswap skip added by `d357fd9bf6a6` ("mm: xswap
support for zswap"). Upstream suppresses readahead for a synchronous device in
the callers instead, and both are intact here: `do_swap_page()` bypasses
`swapin_readahead()` under `SWP_SYNCHRONOUS_IO` (`mm/memory.c:5034-5040`) and
shmem takes `shmem_swap_alloc_folio()` instead of `shmem_swapin_cluster()`
(`mm/shmem.c:2516`). rswap and xswap devices have no `si->bdev`, so they never
set `SWP_SYNCHRONOUS_IO` (`mm/swapfile.c:5011-5012`).

Conclusion: the xswap-only skip in `mm/swap_state.c:897-903,999-1005` keeps
`try_to_unuse()` readaheading synchronous devices exactly as upstream does, and
the only rswap-attributable behaviour change there is enabling readahead for
`SWP_RSWAP` entries, which is intended.

### M5 — "At least one backend" is not enforced

`open`. `mm/Kconfig:134-184` lets both `RSWAP_KV_HTTP` and `RSWAP_KV_REDIS` be
off, which leaves `rswap_backends[]` empty (`mm/rswap.c:133-140`), fails the
late init (`:154-158`) and rejects every device with `-ENODEV` (`:1529-1531`).

### M6 — `CONFIG_RSWAP=y` reserves page_ext memory unconditionally

`deferred`. `need_rswap_page_ext()` returns `true` (`mm/rswap.c:303-311`), so
`struct rswap_page_ext` (33 B) is reserved per base page for the whole system
(~0.8 % of RAM at 4 KiB pages) even when no rswap device is ever created, and
it becomes redundant once slot validity lives in the digest slot (B1/B3).
Gate it on the boot parameter, or drop the page_ext client once the per-cluster
table is the only digest store.

### M7 — `mm/rswap.h` has no include guard

`open`. The header pulls `<linux/swap.h>` and `"swap.h"` only inside
`#ifdef CONFIG_RSWAP`, while the `CONFIG_RSWAP=n` stubs (e.g.
`struct swap_cluster_info *ci`, `mm/rswap.h:138`) rely on the includer having
included them first. It compiles only because of include order in
`mm/swapfile.c`, `mm/shmem.c` and `mm/rmap.c`.

### M8 — Coverage cannot catch the invariants it claims

`open`. The real `rswap_hash_invalidate()` lies outside every extraction range
in `tools/mm/rswap_backend_test.py:315-321`; the harness emulates the release
inline at `:775-778`, so a no-op body passes. `tools/mm/rswap_scale_test.py`
audits object count and size only (`:88-101`) and never compares keys against
the userspace digests, so any deterministic per-page key — including a
reintroduced entry hash — passes, and it defaults to `--rounds 1`. Digest
staleness after a page modification (`AGENTS.md`, "Known Limitations"), page
migration, `rswap_page_ext_copy()` and `rswap_page_ext_reset()` have no
coverage at all.

### M9 — Documentation drift

`open`. `AGENTS.md` describes a design that no longer exists: the per-device
`kvcalloc(si->max, …)` table with `struct rswap_hash_entry { u8 hash[32]; u8
valid; }`, a 64-hex-digit key, digests living in `page_ext`, and "eBPF
integration is postponed". The tree ships the per-VMA digest program
(`mm/rswap.c:596-650`), `VM_HASHED`/`rswap_vma_dup()` (`mm/vma_init.c:146`) and
a sysfs ABI `/sys/kernel/mm/xswap/rswap_attach` (`mm/swapfile.c:173-231`) that
appears in no Documentation file.
`Documentation/admin-guide/sysctl/vm.rst:1044-1048` still calls the 64-digit
digest the KV key. `TODOS.md` ("teardown frees the device table") and
`tools/mm/rswap_swapin_test.rst:74-76` (probes `rswap_flush_batch`) are stale
too.

## MINOR

### Size and layout

- `struct rswap_batch` carries an unused `char data[]` bounce buffer
  (`mm/rswap.c:916,923`): 128 KiB (4 KiB pages) or 512 KiB (16 KiB pages) per
  batch, allocated up to `RSWAP_READ_MAX_INFLIGHT` + writer times, although the
  backends move page images through `struct page` (`mm/rswap_backend.h:34-37`,
  `mm/rswap.c:955`). The documented "1-4 MiB transient read memory" is spent
  entirely on an unused buffer.
- `rswap_prepare_hashes()` allocates under `GFP_NOWAIT` while its caller
  documents "while we may still sleep" (`mm/rswap.c:563`,
  `mm/swapfile.c:2145`); a failed reservation silently changes the key source.

### Ordering and accounting

- `ci->hash_table` is read with `READ_ONCE()` (`mm/rswap.c:438,465,1511`)
  while the slot itself uses acquire; the preceding table-pointer load is not
  ordered against the slot publication on weakly ordered CPUs.
- `rswap_read_leave()` (`mm/rswap.c:1103-1112`) documents that the slot is
  released only after completion, but the inline fallback (`:1193-1199`)
  releases it first, so `read_inflight` can reach 0 before the request
  finished, and `rswap_read_enter_inline()` can push the counter above
  `RSWAP_READ_MAX_INFLIGHT`.
- A key error aborts a request but counts only one failed page
  (`mm/rswap.c:1026-1037`, `:1297-1304`), unlike the batch-failure path
  (`:889-893`).
- `struct swap_info_struct::rswap_dentry` (`include/linux/swap.h:261`) is
  dead; the debugfs helpers use name-based removal
  (`mm/rswap.c:1701-1741`).
- `rswap_vma_dup()` (`mm/rswap.c:577-582`) drops `VM_HASHED`/`rswap_prog` on
  every VMA copy, so `mprotect()`/`mremap()` splits silently stop digest
  resolution for that range (intended for `fork`, likely not otherwise).

### Backends and transport

- Redis builds the bulk key length from `RSWAP_KV_KEY_LEN` rather than from the
  key (`mm/rswap_redis.c:144,617-620`), so a shorter digest would put the NUL
  and neighbouring bytes on the wire.
- A healthy pooled connection is dropped when the last page of a batch returns
  `-ENOENT` (`mm/rswap_redis.c:513-517`), turning routine swapin misses into
  reconnects and `redis_dropped` increments.
- `rswap_redis_transport_error()` treats `-EACCES` (`:365-368`) and `-ENOMEM`
  as transport failures, so a wrong password or an allocation failure burns the
  single retry and inflates `redis_retries`.
- `RSWAP_HTTP_SEND_TIMEOUT_MS` (20 ms, `mm/rswap_http.c:28`) also bounds
  `connect()` (`mm/rswap_sock.c:52-54`), so an endpoint whose RTT approaches
  20 ms fails to connect and cannot be retried.
- The Redis pool semaphore (`mm/rswap_redis.c:356,373`) is shared by writeout
  and the read queue, and its size equals `RSWAP_READ_MAX_INFLIGHT`, so a
  saturated read queue delays reclaim-context writeout by one remote batch.
- The pool never closes idle sockets.
- Redis bypasses the shared transport helpers with its own
  `sock_sendmsg()`/`iov_iter_bvec()` loop (`mm/rswap_redis.c:186-204,291-302`)
  although `mm/rswap_backend.h:99-103` presents them as shared, and
  `mm/rswap_sock.c:5-9` still claims "a backend opens a connection per page
  operation".
- `mm/rswap_sock.c:41-44` justifies the clamp with "a zero timeout would mean
  'never block'", which is wrong for `sk_sndtimeo`/`sk_rcvtimeo` (zero blocks
  indefinitely) and true only for the connect wait.
- `mm/rswap_redis.c:178,183,186` are expected `PARENTHESIS_ALIGNMENT` checkpatch
  warnings; `mm/rswap.c:95,854,941` and `mm/rswap.h:124,143` exceed 80 columns,
  and `mm/rswap.h:124` has a double space.

### Tools and tests

- Verifiers do not retry `write()` on `EINTR` (`tools/mm/rswap_test.c:70-71`,
  `rswap_pageout_test.c:139-141`, `rswap_swapin_test.c:139-141`) and read a
  stale `errno` after `fclose()` (`rswap_test.c:202`, `rswap_swapin_test.c:262`)
  while the demo does retry (`page_hash_user.c:99-104`).
- `rswap_run_test.py:55` calls `cg.rmdir()` in `finally`, which can replace the
  verifier's exit status with a traceback, and writes `memory.zswap.max`
  unconditionally (`:43`).
- No runner passes a `timeout=` to the verifier although
  `rswap_swapin_test.c:156` claims the runner enforces one.
- Documented skips return 4 and are reported as failures (`rswap_test.c:196,218`,
  `rswap_scale_test.py:220`, `rswap_run_test.py:53`).
- `rswap_scale_test.py:33` hardcodes port 6789 and never verifies
  `/sys/kernel/debug/rswap/backend`/`endpoint`, so on a redis- or
  remote-endpoint kernel it writes to the real store and reports a confusing
  audit failure; `:193-208` can leave an extra rswap device swapped in when it
  raises before `device` is assigned.
- `kvswap_server` accepts bodies up to 64 MiB (`tools/mm/kvswap_server.c:55`)
  although the kernel rejects anything that is not exactly one base page
  (`mm/rswap_http.c:167-170`), and neither its header nor `print_usage()` says
  the server is unauthenticated for any `-l` address.
- `kvswap_server.c:522` uses `atoi()` for `--port`; `:300` creates directories
  before validating the key; `handle_get()`'s `open()` follows symlinks in a
  world-readable default directory.
- `kvswap_test.py` has no key-length boundary case (0/63/65/96) and no
  traversal case, and its `test_large_folio` case asserts behaviour the kernel
  can never use.
- `rswap-userspace-demos/page_hash_user.c:180` `mlock()`s the mapping it
  attaches, so the demo can never demonstrate writeout.
- `tools/mm/rswap_backend_test.py:270-275` stubs `rswap_page_key()` by deriving
  a key from `entry.val`, which reads like the banned pattern.
- `rswap-userspace-demos/` contains a compiled binary and has no `.gitignore`.

## What the review confirmed is correct

- The invariant holds in the core and in both backends: no `sha256()` or other
  hash runs over an entry or over page contents, and the only key source is the
  stored digest, emitted by `bin2hex()`.
- Swapin completion is exactly once through `refcount_t`, `req` is freed before
  `ki_complete()`, and no worker touches the submitting stack.
- The synchronous fallback, `WQ_MEM_RECLAIM` and the inflight bound are
  correct; `can_merge()` re-checks every page of both folios.
- Slot release and lookup use store-release/load-acquire pairing, and every
  slot-free path funnels into `swap_range_free()`.
- Page-ext memory is zeroed on every allocation and hotplug path, the reset
  hook covers both free paths and the full order range, and the migration copy
  runs after `__folio_migrate_mapping()` and before the source folio is freed.
- `CONFIG_RSWAP=n` stubs exist for every hook, and requests never mix devices
  because `swap_can_merge()` refuses a differing `si`.
- Upstream's synchronous-device readahead suppression is untouched (M4):
  `do_swap_page()` and shmem still bypass readahead for `SWP_SYNCHRONOUS_IO`,
  which `mm/swap_state.c` never tested.
- RESP and HTTP parsing are strict (`$-1` → `-ENOENT`, non-page-size →
  `-EMSGSIZE`, `NOAUTH`/`WRONGPASS` → `-EACCES`, `Content-Length` required and
  compared), pipelining and partial I/O are handled, and retry-once is
  idempotent because it only fires after the socket was dropped.
- Credentials are sent once per connection, never logged, and
  `rswap.redis_password` is not exposed in sysfs.
- The tools seek the sysctl descriptor to offset zero before each write, which
  matches `*ppos += *lenp`.
