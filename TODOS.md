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
- Keys and per-device counter pointers are taken per batch at submit time and
  live in the kvmalloc'ed `struct rswap_batch`, so no code touches
  `struct swap_info_struct` or the caller's stack-allocated `struct swap_io_ctx`
  after `rswap_read_async()` returns.
- Each batch becomes one work item on the `rswap_read` workqueue, i.e. one
  `rswap_flush_batch()` call, exactly as before. Batch latency
  (`read_avg_ns`/`read_max_ns`) is therefore measured around the real backend
  call in the worker, not at submission.
- `RSWAP_READ_MAX_INFLIGHT` (8) bounds queued plus running batches, which
  bounds both the 32-page bounce buffers (1-4 MiB) and the pinned folios. The
  value matches `RSWAP_REDIS_POOL_MAX`; the measured WILLNEED throughput
  plateaued around eight concurrent batches.
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
- Teardown: `rswap_disable()` calls `flush_workqueue(rswap_read_wq)` before
  it frees the device table and counters. `__swapoff()` has already killed
  `si->users`, run `synchronize_rcu()` and waited for its holders, so no
  submitter can be inside `rswap_read_async()` at that point and the drain
  cannot deadlock.
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
- No new timeout, retry or cancellation logic: a worker blocked in a backend
  receive timeout holds its slot and its locked folios for as long as the
  backend's configured timeout allows, now bounded by 8 slots instead of
  unlimited.
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
