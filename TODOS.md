# rswap TODOs

## Make `submit_read` asynchronous

- [ ] Change `rswap_submit_read()` to queue/dispatch remote reads and return
  without waiting for the responses. When a request finishes, invoke its
  completion callback, following the normal asynchronous swapin lifecycle.

Currently `swap_read_submit()` calls `rswap_submit_read()` directly, and
`rswap_submit()` waits inside `rswap_flush_batch()`. The Redis backend sends
up to 32 pipelined GET commands, receives every response in that batch, and
only then allows the caller to submit the next batch. Consequently, one
`MADV_WILLNEED` caller blocks on remote I/O and has only one batch in flight.
Connection pooling enables overlap between callers, but not within one
caller's submission stream.

Implementation requirements:

- Separate submission from completion. Permit several bounded requests/batches
  in flight so one prefetch caller can overlap network I/O. Merely moving all
  reads onto one serial worker would preserve the throughput bottleneck.
- Initialize and retain the `swap_iocb` and its completion callback before
  publishing queued work. Do not retain the caller's stack-allocated
  `swap_io_ctx`: `swap_read_submit()` clears its pointers after submission.
- Keep request buffers, digest keys, folios, and required swap-device/table
  references valid until the I/O finishes. Preserve folio locking and prevent
  swapoff/device teardown from freeing state used by outstanding requests.
- After all batches belonging to a request finish and successful read data is
  copied to the destination pages, invoke
  `sio->iocb.ki_complete(&sio->iocb, result)` exactly once. Use the existing
  `swap_fs_read_complete()` / `swap_read_end()` path to mark successful folios
  uptodate, unlock them, wake waiters, and release the `swap_iocb`. Do not touch
  it after the callback frees it. Return the full request length on success
  or an appropriate error on failure; never expose partial data as uptodate.
- Bound queue depth, buffer memory, and connection use; maintain forward
  progress under memory pressure and `GFP_NOIO`. Handle allocation/queue
  failures, timeouts, retries, and teardown without lost or double completion.
- Preserve userspace-only digest keys, per-entry lookup, missing-key errors,
  and correct page/batch/error accounting. Never derive fallback keys.

Validation:

- Trace one `MADV_WILLNEED` caller on a fully evicted 512 MiB mapping and
  demonstrate overlapping reads without multiple userspace callers. Measure
  submission latency separately from time until all remote reads complete.
- Adapt `rswap_swapin_test.py` to await actual I/O completion before checking
  residency and bandwidth: its current synchronous-backend test expects all
  reads complete when WILLNEED returns. Do not count swap-cache hits as remote
  throughput or let the verification scan hide incomplete prefetch.
- Verify every byte, exact remote page/byte counts, and normal fault waiters;
  exercise transport failures, partial batches, memory pressure, concurrent
  faults, and swapoff with outstanding I/O. Cover both HTTP and Redis.

Motivation measured on November 2, 2026, kernel `aeb11a14094d`, Redis,
16 KiB pages, 32-page batch limit, unchanged `vm.page-cluster=3`:

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
