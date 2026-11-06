Cold rswap read performance
===========================

``rswap_swapin_test.c`` and ``rswap_swapin_test.py`` measure remote swapin
with a 512 MiB anonymous mapping by default. They are separate from the
existing integrity and whole-mapping pageout tests.

The backend and the endpoint are boot parameters (``rswap.backend=``,
``rswap.host=``, ``rswap.port=`` and the Redis ones), never a compiled-in
address: the runner reads ``/sys/kernel/debug/rswap/backend`` and
``/sys/kernel/debug/rswap/endpoint`` and uses whatever the running kernel
booted with. It does not start or configure a server, so the endpoint must
already be reachable.

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

Each run fills a fresh mapping, computes SHA-256 over every native base page,
attaches the 64 hexadecimal digits through ``/proc/sys/vm/rswap/attach``, and
records them in ``digests.txt``. That is the legacy attach path: rswap's key is
96 hexadecimal characters, the 48-byte digest slot, of which this interface
fills the first 32 bytes and leaves the rest zero. It calls ``MADV_PAGEOUT`` and
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

The main thread waits for all workers, records how long their submission took
(``SUBMITTED``), and then waits until ``mincore()`` reports every page
resident again (``LOADED``). For a swap-cache folio that only happens once
the folio is uptodate, which the completion path sets when the remote read
finished, so on an asynchronous backend ``LOADED`` is a real completion gate
and the gap between the two is the completion tail. It then verifies every
word against the original pattern. Full content verification has its own
timing and must require no additional remote reads.

What the measurements mean
--------------------------

``result.json`` includes cold-page counts, submission and load times, actual
remote bytes/pages/batches, payload MiB/s, submission MiB/s, completion-tail
seconds, worker count, connection reuse/retry counters, and integrity status.
Load time and bandwidth use ``LOADED``; the submission figures only cover the
``MADV_WILLNEED`` calls resp. the page-fault loads. Every successful run must
read exactly one mapping's worth of remote data with no I/O errors or writes
during the measured read phase.

WILLNEED is a hint and does not promise completed I/O on return. This test
measures the installed backend's behavior and requires completion instead of
assuming it: every page must be resident and every expected remote read done
by ``LOADED``, and ``read_inflight`` must be zero at that point. A single
WILLNEED call now batches pages and overlaps several batches without further
userspace callers; the trace's peak active batch count and the debugfs
``read_peak_inflight`` line report whether it did, and ``read_fallbacks``
counts batches that had to be moved in the submitting task (no queue slot or
no workqueue). ``read_submits`` and ``read_submit_avg_ns`` describe the
submission path itself. Throughput is computed from total wall time, not the
sum of overlapping batch durations.

Temporary fprobe entry/return events on the backend's load function measure
the batch-size histogram, peak simultaneous read batches, and per-batch p50,
p95, p99 and maximum latency. The traced symbol is
``rswap_<backend>_load``, with ``<backend>`` taken from
``/sys/kernel/debug/rswap/backend`` (``http`` or ``redis``); writeout is not
probed by this runner. These are backend-call latencies, not individual
page-fault latency or bare network RTT. ``do_madvise`` probes validate that
the WILLNEED calls cover the mapping exactly once with disjoint ranges. Read
batches run on the backend's worker threads, so a batch is paired per thread
but is not confined to the calling worker's advice window. The runner rejects
incomplete traces and trace-buffer overruns. Raw traces and per-CPU trace
statistics are retained alongside the results.

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
