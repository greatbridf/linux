# Remote Swap Investigation

Date: October 29, 2026.
Initial source baseline: `5749184e2c994e4f3f7d4c680d5aa7f406b56971`.
Post-reboot source baseline: `7048ca1cab502`.
Current tested source: `f457cbea357a8`.
Running kernel: `7.3.0-rust-17054-gf457cbea357a #51.tl4`, ARM64,
16 KiB base pages, approximately 16 GiB RAM.

## Second-Reboot Results

The remote-swap-only test matrix passes on the current kernel. Zswap-specific
tests were excluded at the user's request; no zswap settings were changed.
The temporary server used fresh storage and rswap was the only active swap
device during the integrity tests.

| Workload | Rounds | Result |
| --- | --- | --- |
| 8 MiB base pages | 20 | All bytes match; 512/512 pages evicted each round |
| Fresh 32 MiB THP mappings | 3 separate processes | All bytes match; each mapping confirmed entirely THP-backed before reclaim |
| 64 MiB base pages | 5 | All bytes match; first round evicted 4,091/4,096 pages, others 4,096/4,096 |
| 128 MiB base pages | 3 | All bytes match; 8,192/8,192 pages evicted each round |
| Four concurrent 16 MiB workloads | 5 each | All bytes match; 1,024/1,024 pages evicted each round |

The complete matrix performed **51 successful rounds, comparing 1,280 MiB**
and observing **81,915/81,920 base pages evicted**. Every 64-bit word was
compared with its original generated pattern, including the tail of each
16 KiB page. All ten verifier processes exited successfully, and every test
cgroup had zero swap usage after exit.

- No remote read errors, Oops, or new kernel warnings appeared in dmesg.
- All 21,548 server objects checked were exactly 16,384 bytes.
- Protocol tests pass 11/11; actual-source backend regressions pass.
- The temporary remote device was successfully destroyed after verification.
- The server stopped, test cgroups were removed, and the original
  `/dev/zram0` swap was restored at priority 100 with zero usage.
- Kernel taint remained 0; no verifier task was left behind.

The initial attempt passed another 20 serial rounds and the first THP round,
but the reused THP mapping had zero `AnonHugePages` in round two, so the
verifier returned SKIP (exit 4). This is not a data mismatch or remote I/O
failure. Repeating the THP test in three fresh processes verified huge-page
backing and integrity each time. With `CONFIG_THP_SWAP` disabled on this
16 KiB-page kernel, reclaim still splits THPs before swap-out; these tests
do not establish unsplit large-folio swap-out correctness.

Complete-run artifacts are in `/tmp/rswap-reboot-z2nhygxq` (root-owned):
`results.json`, per-workload logs, `object-sizes.json`, `new-dmesg.txt`, and
before/after kernel snapshots. Preliminary-run artifacts, including the
THP skip, are in `/tmp/rswap-reboot-y6vc5q8j`. No kernel code was changed
during this rerun.

## First-Reboot Findings and Tests

These historical results were obtained on
`7.3.0-rust-17053-g7048ca1cab50 #48.tl4`, before the current cleanup fix.

**High: freeing remote swap slots crashes after zswap has been enabled.**
Remote device setup deliberately skips `zswap_swapon()`, leaving its
`zswap_trees[type]` NULL. `swap_range_free()` nevertheless calls
`zswap_invalidate()` unconditionally. Once zswap has ever been enabled,
that function dereferences the missing tree. Turning zswap back off does
not restore the `zswap_never_enabled()` fast path.

Reproducer on the rebooted kernel: make rswap the only active swap device,
enable global zswap, and run the bounded 8 MiB verifier for five rounds
with `memory.zswap.max=0`. Every round evicted all 512 pages and matched
all bytes, but final `munmap()` caused this Oops at uptime 203.129 seconds:

```text
Unable to handle kernel NULL pointer dereference at virtual address 0000000000000008
pc : zswap_invalidate+0x78/0xa0
Call trace:
 zswap_invalidate
 __swap_cluster_free_entries
 __swap_cache_do_del_folio
 swap_cache_del_folio
 folio_free_swap
 free_pages_and_swap_cache
 tlb_flush_mmu
 tlb_finish_mmu
 unmap_region
 ...
 __arm64_sys_munmap
```

Fix: skip zswap invalidation only for `SWP_RSWAP`, matching the existing
store/load bypasses. Architecture invalidation, block-device notification,
cleanup ordering, and swap accounting remain unchanged. The regression
compiles the actual `swap_range_free()` source with shims and covers
single/multiple slots on rswap, ordinary xswap, file-backed swap, and block
swap with/without a notification callback. It fails on `7048ca1cab502`
and passes with the guard. This is not runtime validation of the new fix.

Before enabling global zswap, all of these live tests exited successfully
and left zero test-cgroup swap usage:

| Workload | Rounds | Result |
| --- | --- | --- |
| 8 MiB base pages | 10 | All bytes match; 512/512 pages evicted each round |
| 8 MiB, `memory.zswap.max=0` | 5 | All bytes match; allocation-gate fix validated |
| Confirmed 32 MiB THP mapping | 1 | All bytes match; 2,048/2,048 pages evicted |
| 64 MiB base pages | 3 | All bytes match; 4,096/4,096 pages evicted each round |
| Four concurrent 8 MiB workloads | 3 each | All bytes match; one round evicted 510/512 pages, others 512/512 |

These are **31 clean rounds, 440 MiB compared**, with 28,158 base pages
observed evicted. THPs are split before swap-out because `CONFIG_THP_SWAP`
is disabled; unsplit large-folio validation remains outstanding.
The global-zswap test compared another 40 MiB over five rounds without
mismatches, but is a **failed test** because cleanup crashed.
No remote read errors appeared in dmesg during this reboot's tests.
Protocol tests pass 11/11; actual parser, submit-path, and new slot-cleanup
regressions pass. `make -C tools/mm rswap_test kvswap_server` and
`make O=build LLVM=1 -j12 Image` succeed without new warnings.
Checkpatch reports zero errors/warnings; `git diff --check` passes.

Live artifacts are in `/tmp/rswap-reboot-zzlzix_d` (root-owned), including
per-workload logs and server storage under `kv/`. The initial dmesg
snapshots predate the crash; `oops-dmesg.txt` captures the later Oops.
At the end of that run, the crashed verifier remained in uninterruptible
`exit_mmap` as PID 1304839, and the kernel was tainted 128.
Further live swap tests and remote swapoff
were stopped. Global zswap is back to `N`, and the original zram swap was
restored through `dev-zram0.swap` at priority 100. Remote type 0 remains
active with 8,224 KiB used; server PID 1304803 is deliberately left running
on `127.0.0.1:6789` with that backing storage.

That run required another reboot into the cleanup fix; stopping its server
or attempting remote swapoff was unsafe on the Oops-tainted kernel.
The second reboot cleared that state, and its results are recorded above.

## Initial Investigation Findings

1. **Critical: silent page-content corruption.**
   `tools/mm/kvswap_server.c:339` previously read a request once into an
   8192-byte buffer and stored only the bytes returned, ignoring
   `Content-Length`. All 38,028 objects present at the start were 7,988
   bytes instead of a complete 16,384-byte page. Fragmented headers failed
   with HTTP 400; fragmented bodies could be acknowledged with no data.
   `mm/rswap.c:194` previously returned success after premature EOF or a
   receive failure, causing the swap completion to mark partial data
   uptodate. A live 1 MiB test evicted all 64 pages and reported 67,200
   mismatching 64-bit words, starting at byte 7984, without a new read
   error in dmesg. Earlier reclaim of the verifier's own unprotected
   runtime also ended with a segmentation fault; the test now locks its
   existing runtime pages and leaves only its test mapping reclaimable.
   Fix: receive the complete declared request body, publish it by atomic
   rename, loop over partial socket/file writes, and reject incomplete
   or incorrectly framed responses in the kernel.

2. **High: large folios did not have stable swap-slot addressing.**
   `mm/rswap.c:310` previously stored an entire folio under its first
   entry's key. Later base-page reads of the remaining entries cannot
   find their data. One bvec is not necessarily one base page, and
   `kmap_local_folio()` only guarantees a single-page mapping. The old
   multi-bvec rejection also called an uninitialized completion callback.
   Fix: transfer one base page per swap entry, use a page-sized bounce
   buffer, and initialize completion before handling the request.
   The actual-source shim test reproduces the old one-object write and
   verifies split-folio reads, multiple bvecs, and missing-page failure
   with the fix. This is not a booted-kernel large-folio test.

3. **High: the intended one-second socket timeouts were not installed.**
   `mm/rswap.c:62` passed a four-byte integer to socket options requiring
   a timeval and ignored their errors. Inspection of
   `net/core/sock.c:sock_copy_user_timeval()` proves this returns `-EINVAL`.
   Dmesg contained four connect failures with `-512` (`-ERESTARTSYS`),
   followed by read errors: these particular errors were interrupted
   connects, not demonstrated checksum failures.
   Fix: set the kernel socket's send and receive timeouts using the
   proper internal interfaces and preserve receive errno. Diagnostics
   now include the swap type, offset, and errno. Signals and genuine
   server failures can still fail I/O; they must not become successful
   reads.

4. **Medium: a zswap limit incorrectly disabled remote swap.**
   `mm/swapfile.c:1646` and `mm/swapfile.c:1679` treated rswap as
   zswap-only xswap. With `memory.zswap.max=0`, a live 1 MiB test evicted
   zero of 64 pages. Fix: exempt `SWP_RSWAP` from those allocation gates.
   Remote reads also bypass `zswap_load()`, because rswap device setup
   does not allocate a zswap tree. This avoids dependence on whether
   zswap was ever enabled.

The previous `swap_fs_prepare_rw()` change also removed file-backed
kiocb flags and I/O priority. Restore `init_sync_kiocb()` for non-NULL
backing files, retaining zero initialization for file-less devices.

## Pre-Reboot Verification

The following results were obtained before booting `7048ca1cab502`, on
`7.3.0-rust-17051-gd189377a39c6-dirty`.

- Original server: initial eight-test suite had five failures and one
  error; 4 KiB and missing-key tests passed.
- Fixed server: all 11 protocol tests pass, including 4/16/64 KiB and
  2 MiB payloads, fragmented headers/bodies, duplicate/oversized lengths,
  missing and empty values, and an interrupted update preserving old data.
- Same 11 tests pass with AddressSanitizer and UndefinedBehaviorSanitizer.
- Actual original backend source: premature EOF, wrong/missing/duplicate
  lengths, lost timeout errno, and large-folio addressing tests fail.
- Actual revised backend source: parser and submit-path shim tests pass.
- Fixed server with the unchanged running kernel: 1 MiB test passes;
  five 8 MiB cycles and three additional 8 MiB cycles pass, evicting all
  512 pages each time and comparing every word.
- A confirmed 32 MiB THP mapping passes after all 2,048 base pages are
  evicted and read back. This kernel has `CONFIG_THP_SWAP` disabled for
  16 KiB pages, so reclaim splits THPs before writing; this does not prove
  unsplit large-folio swap-out.
- All live test cgroups were removed and their remaining swap usage was zero.
- No new dmesg read errors appeared during successful integrity tests.
- `make -C tools/mm rswap_test kvswap_server` passes without warnings.
- `make O=build LLVM=1 -j12 Image` links the ARM64 kernel successfully.
- Changed code and new test files pass checkpatch without errors/warnings;
  `git diff --check` passes.

## Repeating Tests

Run from the kernel source root:

```sh
make -C tools/mm rswap_test kvswap_server
python3 tools/mm/kvswap_test.py
python3 tools/mm/rswap_backend_test.py
sudo python3 tools/mm/rswap_run_test.py --size-kib 8192 --rounds 5
sudo python3 tools/mm/rswap_run_test.py --size-kib 32768 --rounds 1 --huge
```

Run live commands with a fresh rswap backend as the only active swap device.
Use a fresh process for each THP repetition, since the mapping may no longer
be huge-page-backed after swap-in.
The runner requires that every active swap device is an rswap device,
creates a bounded cgroup, and reclaims only that cgroup's pages. It reports
SKIP (exit 4) if no pages leave RAM, avoiding a false integrity pass.

## Remaining Limitations

- The cleanup fix and preceding I/O fixes are now booted and tested for
  the remote-only matrix. Full-kernel timeout, failure-injection,
  active-page swapoff, and unsplit large-folio validation remain outstanding.
  Empty-device destruction passed. Zswap-specific validation was excluded
  from the latest rerun.
- This reboot used fresh server storage, not the old truncated objects.
  A successful fresh-data test does not establish integrity of old live
  swap entries or restore bytes already lost by the old implementation.
- The SHA-256 key hashes the swap entry, not the payload. Exact-length
  checks and these comparisons do not provide a payload checksum, network
  authentication, persistence across server crashes, or cross-client key
  isolation. The endpoint is still hardcoded to loopback.
- The single-threaded server is not pinned in RAM. Heavy global reclaim
  could evict its own working set into its backing service, creating a
  dependency cycle. Global OOM stress was deliberately not run on this host.
- Per-operation socket timeouts do not impose a total request deadline
  against a peer that continually sends tiny amounts of data.
- Under the kernel threat-model document, these findings are treated as
  correctness bugs in an unofficial development fork. No upstream
  vulnerability claim or external report was made.

Maintainers identified by `scripts/get_maintainer.pl`: Andrew Morton,
Chris Li, Kairui Song; lists: `linux-mm@kvack.org` and
`linux-kernel@vger.kernel.org`. No mail was sent.

Investigation, fixes, regression tests, and this report were produced with
Codex assistance in response to the request to investigate remote-swap read
errors and verify page contents. Human review and DCO certification are
required before submission; no Signed-off-by tag was added.
