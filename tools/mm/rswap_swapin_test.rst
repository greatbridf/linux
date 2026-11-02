Cold rswap read performance
===========================

``rswap_swapin_test.c`` and ``rswap_swapin_test.py`` measure remote swapin
with a 512 MiB anonymous mapping by default. They are separate from the
existing integrity and whole-mapping pageout tests.

Build and run with the configured KV server reachable, rswap enabled,
``CONFIG_FPROBE_EVENTS`` enabled, and debugfs/tracefs mounted::

    make -C tools/mm rswap_swapin_test
    sudo python3 tools/mm/rswap_swapin_test.py --takeover-swap \
        --mode willneed --workers 1 --output /tmp/swapin-willneed-1
    sudo python3 tools/mm/rswap_swapin_test.py --takeover-swap \
        --mode willneed --workers 8 --output /tmp/swapin-willneed-8
    sudo python3 tools/mm/rswap_swapin_test.py --takeover-swap \
        --mode fault --workers 8 --output /tmp/swapin-fault-8

The output directory must be new. ``--size-kib`` changes the mapping size;
``--workers`` accepts 1..32 and must divide the native page count. Stop
other rswap workloads during measurement because counters and probes cover
all reads through the selected backend.

Preparing genuinely cold reads
------------------------------

Each run fills a fresh mapping, computes and attaches SHA-256 digests in
userspace, and records them in ``digests.txt``. It calls ``MADV_PAGEOUT`` and
then uses its bounded cgroup's ``memory.reclaim`` to remove remaining
swap-cache residency. Before measurement it requires every page to be
nonresident according to ``mincore()`` and every PTE to be swapped according
to ``pagemap``. This avoids reporting memory-cache hits as network bandwidth.
The mapping uses base pages and the test leaves ``vm.page-cluster`` unchanged.

Workers are created after reclaim, before timing, and start together at a
barrier. Each worker owns one contiguous, disjoint slice of the mapping:

* ``willneed`` issues one ``MADV_WILLNEED`` over each worker's slice.
* ``fault`` loads one word per native page, retaining a checksum so the
  compiler cannot remove the accesses.

The main thread waits for all workers and records elapsed wall time. It
checks residency again, pauses for the runner to capture counters and
traces, and verifies every word against the original pattern. Full content
verification has its own timing and must require no additional remote reads.

What the measurements mean
--------------------------

``result.json`` includes cold-page counts, load and verification times,
actual remote bytes/pages/batches, payload MiB/s, worker count, connection
reuse/retry counters, and integrity status. Every successful run must read
exactly one mapping's worth of remote data with no I/O errors or writes
during the measured read phase.

Temporary fprobe entry/return events on ``rswap_flush_batch`` measure the
batch-size histogram, peak simultaneous read batches, and per-batch p50,
p95, p99 and maximum latency. These are backend-call latencies, not individual
page-fault latency or bare network RTT. ``do_madvise`` probes validate that
the WILLNEED calls cover the mapping exactly once with disjoint ranges.
The runner rejects incomplete traces and trace-buffer overruns. Raw traces
and per-CPU trace statistics are retained alongside the results.

WILLNEED is a hint and does not universally promise completed I/O on return.
This test measures the installed backend's behavior: it requires all pages
resident and all expected remote reads complete when the workers finish.
A single WILLNEED call can batch pages without overlapping backend calls.
Multiple workers demonstrate overlap only when the trace reports more than
one active batch. Throughput is computed from total wall time, not the sum
of overlapping batch durations.

Cleanup and limits
------------------

The runner restores swap devices disabled by ``--takeover-swap``, destroys
only the rswap device it creates, and removes its cgroup, trace instance,
and temporary events. It records any cgroup swap charge still visible after
the verifier exits; device teardown is separate from the measured load.
Reclaim can reject unrelated unattached pages with ``-ENODATA`` during
preparation; counters are sampled only after full eviction completes.

Backend objects are retained for auditing against ``digests.txt``. The
runner does not delete keys that might predate the test. This is a bounded
performance experiment on the running kernel, not a benchmark establishing
physical link capacity. Repeated runs are needed to quantify variability.
