# rswap TODOs

## Make `submit_read` asynchronous

- [x] Change `rswap_submit_read()` to queue/dispatch remote reads and return
  without waiting for the responses. When a request finishes, invoke its
  completion callback, following the normal asynchronous swapin lifecycle.

The paragraph below is the original problem statement; the section after it
records how the async path is implemented and what it does not solve.

Originally `swap_read_submit()` called `rswap_submit_read()` directly, and
`rswap_submit()` waited inside `rswap_flush_batch()`. The Redis backend sends
up to 32 pipelined GET commands, receives every response in that batch, and
only then allows the caller to submit the next batch. Consequently, one
`MADV_WILLNEED` caller blocked on remote I/O and had only one batch in flight.
Connection pooling enabled overlap between callers, but not within one
caller's submission stream.

### Implementation

- `rswap_submit_read()` calls `rswap_read_async()`. It resolves every key,
  addresses every base page and prepares `sio->iocb` in the submitting task,
  then dispatches the request's batches and returns. Writeout stays
  synchronous: reclaim wants the writeback flag cleared before it continues.
- Keys and a referenced counter block are taken per batch at submit time and
  live in the `kzalloc_obj()`'ed `struct rswap_batch`, so no code touches
  `struct swap_info_struct` or the caller's stack-allocated `struct swap_io_ctx`
  after `rswap_read_async()` returns. The batch also carries the swap type, so
  the worker needs no device at all.
- Each batch becomes one work item on the `rswap_read` workqueue, i.e. one
  `rswap_flush_batch()` call, exactly as before. Batch latency
  (`read_avg_ns`/`read_max_ns`) is therefore measured around the real backend
  call in the worker, not at submission.
- `RSWAP_READ_MAX_INFLIGHT` (8) bounds queued plus running batches, which
  bounds the pinned folios and the per-batch bookkeeping (`RSWAP_BATCH_MAX`
  keys of `RSWAP_KV_KEY_LEN` bytes plus one `struct rswap_kv_page` per page;
  there is no page buffer). The value matches `RSWAP_REDIS_POOL_MAX`; the
  measured WILLNEED throughput plateaued around eight concurrent batches.
- Forward progress under pressure: a batch that cannot take a slot, an item
  the workqueue refuses, and a missing request structure all fall back to
  moving that batch in the submitting task, which is the previous synchronous
  behaviour. `WQ_MEM_RECLAIM` keeps a worker runnable while reclaim waits.
- Completion is exactly once, from a `refcount_t` that the submitter holds
  once and every dispatched batch holds once. The last batch to finish calls
  `sio->iocb.ki_complete(&sio->iocb, ret ? ret : sio->len)`; the normal
  `swap_read_end()` then marks the folios uptodate, unlocks them and frees the
  `swap_iocb`. The first negative errno fails the whole request, so partial
  batch success is never exposed as uptodate.
- Teardown: `rswap_disable()` calls `flush_workqueue(rswap_read_wq)` and drops
  the device's reference to the counter block. It does not free a digest
  table, because there is none per device: digest slots belong to the swap
  clusters (`ci->hash_table`, one slot per offset, freed with the cluster by
  `rswap_hash_table_free()`), and the counter block is freed by the last
  `rswap_stats_put()`, i.e. once no worker and no queued batch holds a
  reference. `__swapoff()` has already killed `si->users`, run
  `synchronize_rcu()` and waited for its holders, so the drain cannot
  deadlock.
- New `stats` lines: `read_inflight`, `read_peak_inflight`, `read_fallbacks`,
  `read_submits` and `read_submit_avg_ns`. Page, batch, error, `no_entry` and
  batch-latency counters keep their previous meaning.
- `tools/mm/rswap_swapin_test.c` now reports `SUBMITTED` (submission latency)
  separately from `LOADED` (every page of the mapping resident again, which
  for a swap-cache folio means the remote read completed) and waits for the
  latter. `tools/mm/rswap_swapin_test.py` gates on `read_inflight == 0` after
  `LOADED`, on `read_pages == pages`, and reports submission bandwidth,
  completion-tail time, peak in-flight batches and inline fallbacks.

### Validation

- `tools/mm/rswap_backend_test.py` compiles the real async code with
  `queue_work()` running the work item inline, so an asynchronous read request
  completes exactly once through `rswap_read_batch_work()` and releases its
  slot; it also covers the no-workqueue inline fallback.
- Live, on a booted kernel with the new code:

```sh
sudo python3 tools/mm/rswap_swapin_test.py --takeover-swap \
    --mode willneed --workers 1 --output /tmp/rswap-willneed-1
sudo python3 tools/mm/rswap_swapin_test.py --takeover-swap \
    --mode willneed --workers 8 --output /tmp/rswap-willneed-8
sudo python3 tools/mm/rswap_swapin_test.py --takeover-swap \
    --mode fault --workers 8 --output /tmp/rswap-fault-8
sudo python3 tools/mm/rswap_pageout_test.py --takeover-swap \
    --output /tmp/rswap-pageout-base
```

The `willneed 1` run is the acceptance test: `read_peak_inflight` must exceed
one concurrent batch for a single caller, `SUBMITTED` must be much smaller
than `LOADED`, and the run must still verify every byte with no additional
remote reads. Both backends need a pass.

### Remaining follow-ups

- The bound is a compile-time constant. An adaptive or per-device depth, and
  HTTP connection pooling (which would make the HTTP backend pay the batch
  round trip only once), are not implemented.
- ~~No new timeout~~: the request deadline added in `bb27e27f073a` bounds a
  whole request (connect, send and two receive timeouts, plus both attempts of
  the Redis retry), so a worker can no longer pay one receive timeout per
  parser byte. A worker still holds its slot and its locked folios for the
  length of that budget, now bounded by 8 slots instead of unlimited.
- Writeout is still synchronous. It could reuse the same batch/work item
  machinery if the writeback-flag latency of reclaim turns out to matter.
- The reported `read_peak_inflight` is a boot-lifetime maximum reset at device
  creation, not a per-run maximum.

### Motivation (historical measurement, synchronous backend)

Measured on November 2, 2026, kernel `aeb11a14094d`, Redis, 16 KiB pages,
32-page batch limit, unchanged `vm.page-cluster=3`:

| Cold 512 MiB load | Time | Payload bandwidth | Peak concurrent batches |
|---|---:|---:|---:|
| Page faults, 1 thread | 61.42 s | 8.34 MiB/s | 1 |
| WILLNEED, 1 caller | 52.72 s | 9.71 MiB/s | 1 |
| WILLNEED, 2 callers | 36.59 s | 13.99 MiB/s | 2 |
| WILLNEED, 4 callers | 23.67 s | 21.63 MiB/s | 4 |
| WILLNEED, 8 callers | 22.76 s | 22.50 MiB/s | 8 |
| Page faults, 8 threads | 24.79 s | 20.66 MiB/s | 8 |

All six runs started with 32,768/32,768 pages nonresident, read exactly
512 MiB remotely, and passed full content verification without further
remote reads during verification. No measured read errors or Redis retries
occurred. These are individual runs, not a proof of physical link capacity.

## What the November 2026 review series changed

The series from `e19c7859301a` to `864af43d0c7a` fixed every BLOCKER and MAJOR
finding recorded in `REVIEW-FINDINGS.md` except M6. In rswap terms:

- digest slot validity is explicit (`u8 valid`, release/acquire), a reserved or
  released slot reports "no digest" instead of 48 zero bytes, and
  `rswap_hash_invalidate()` clears `valid` and keeps the object for the
  cluster's lifetime instead of leaking it;
- shmem digest staging no longer frees the entry `xa_store()` just stored;
- the HTTP backend moved to the shared page transport and builds again;
- `kvswap_server` and both source harnesses accept the 96 hex character key;
- a read batch carries its own counters reference and `swapin_walk_pmd_entry()`
  pins the device across `swap_read_submit()`, so nothing reaches a torn-down
  device; the digest program pointer is RCU protected;
- a configuration without any KV backend is a build error;
- `mm/rswap.h` is self-contained, the read slot accounting is correct, a key
  error fails every page that did not move, and the dead `rswap_dentry` field
  is gone;
- the transport has a per-request deadline, a separate connect timeout, and
  classifies Redis errors and pooled-connection drops correctly;
- the live runners audit backend keys against the digest manifest, verify the
  boot-selected endpoint, bound their verifier with `--timeout`, and report
  documented skips as exit 77.

## Deferred from the review

- M6: `CONFIG_RSWAP=y` reserves `struct rswap_page_ext` for every base page
  even when no rswap device exists (`need_rswap_page_ext()` returns true). Gate
  it on the boot parameter, or drop the page_ext client once the per-cluster
  slot is the only digest store.
- The Redis connection pool semaphore is shared by writeout and the read queue
  and its size equals `RSWAP_READ_MAX_INFLIGHT`, so a saturated read queue
  delays reclaim-context writeout by one remote batch.
- The Redis pool never closes idle sockets; a connection is reused or dropped
  only when a batch finds it broken.
- Live coverage for folio migration and for `rswap_page_ext_copy()` /
  `rswap_page_ext_reset()` does not exist; the page_ext fallback and the
  migration hooks are only covered by source inspection.
