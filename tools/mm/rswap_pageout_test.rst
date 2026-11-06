Whole-mapping rswap pageout test
===============================

``rswap_pageout_test.c`` is a separate copy of the integrity verifier,
specialized for one ``madvise(mapping, size, MADV_PAGEOUT)`` call. It attaches
a userspace SHA-256 digest to every native page, waits for the runner to
enable tracing, then calls MADV_PAGEOUT once over the entire mapping. It
does not split the range, retry pageout, or write to ``memory.reclaim``.

Build and run on a kernel with rswap and ``CONFIG_FPROBE_EVENTS`` enabled,
with debugfs and tracefs mounted and the configured KV server reachable::

    make -C tools/mm rswap_pageout_test
    sudo python3 tools/mm/rswap_pageout_test.py --takeover-swap \
        --output /tmp/rswap-pageout-base

The default mapping is 512 MiB. ``--huge`` requests THP and checks that the
whole mapping has huge-page backing before pageout. ``--size-kib`` allows
smaller runs. The output directory must not already exist.

``--takeover-swap`` temporarily disables other swap devices and restores
them afterward. The runner creates an rswap device if necessary and removes
only the device it created. The workload runs in a bounded cgroup with
zswap disabled for that cgroup. The backend and the endpoint are the boot
parameters (``rswap.backend=``, ``rswap.host=``, ``rswap.port=``, and the
Redis ones), not an address compiled into ``mm/rswap.c``: the runner reads
``/sys/kernel/debug/rswap/backend`` and ``/sys/kernel/debug/rswap/endpoint``,
does not start a server, and does not change backend configuration.

Measurements
------------

The runner creates a private tracefs instance and four temporary fprobe
events on ``do_madvise`` and ``rswap_flush_batch``. ``rswap_flush_batch()`` is
the core function every writeout batch goes through, so the probes are backend
independent; the swapin runner traces the backend's load function instead. Entry/return pairing
checks that there was exactly one MADV_PAGEOUT covering the requested
address and length, counts pages in every write batch, and measures peak
simultaneous backend batches across all writer threads. It checks the
trace for dropped events and compares traced pages/batches with debugfs
counters. Other rswap workloads should be stopped during this measurement:
the counters and batch probes cover the selected backend globally.

A peak of one means that the measured call submitted batches serially;
multiple pages in each batch still share the backend's batched operation.
This does not imply that separate concurrent callers cannot overlap I/O.
All measured batches must finish before the MADV_PAGEOUT call returns.

Three different results are reported separately:

* ``written_pages`` / ``written_bytes``: successful backend writes during
  the MADV_PAGEOUT call.
* ``swapped`` / ``present``: swap versus present PTEs from
  ``/proc/self/pagemap`` immediately after the call.
* ``nonresident``: pages reported absent by ``mincore()``. Pages with swap
  PTEs may remain resident in swap cache, so writing the full mapping to
  Redis does not imply that the full mapping's RAM has been freed.

The verifier checks every byte after the runner captures the writeout
measurements. Reads satisfied from swap cache do not exercise the remote
load path. For complete physical eviction and swapin integrity coverage,
use the existing ``rswap_run_test.py`` reclaim test as well.

Results and cleanup
-------------------

``result.json`` records syscall time, counter snapshots, batch-size
histogram, writer TIDs, peak overlap, page-table/residency counts, and
verification status. ``trace.txt``, per-CPU trace statistics, and
``verifier.log`` preserve the underlying evidence. ``digests.txt`` lists
the exact userspace keys attached to this mapping for a subsequent backend
audit. The test retains backend objects; it does not delete potentially
preexisting objects with the same keys.

The runner removes its trace instance/events and cgroup and restores the
original swap configuration on exit, including test failures. No kernel
code or global readahead setting is changed.
