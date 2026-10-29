# Remote Swap Investigation

Date: October 29, 2026.
Source baseline: `5749184e2c994e4f3f7d4c680d5aa7f406b56971`.
Running kernel: `7.3.0-rust-17051-gd189377a39c6-dirty`, ARM64,
16 KiB base pages, approximately 16 GiB RAM.

## Findings

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

## Verification

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
sudo python3 tools/mm/rswap_run_test.py --disable-zswap
```

The final command currently reproduces the allocation failure on the old
running kernel; repeat after booting the rebuilt kernel to validate the gate
fix. The runner requires that every active swap device is an rswap device,
creates a bounded cgroup, and reclaims only that cgroup's pages. It reports
SKIP (exit 4) if no pages leave RAM, avoiding a false integrity pass.

## Remaining Limitations

- The rebuilt image is `build/arch/arm64/boot/Image`. It has not been
  installed or booted; no host reboot or swap-device destruction was done.
  Full-kernel timeout, failure-injection, zswap-enabled, swapoff, and
  unsplit large-folio validation remain outstanding.
- The fixed server is running as PID 498991 on `127.0.0.1:6789`, using
  the original `/tmp/rswap-test-O28izO` directory. Its log is
  `/tmp/rswap-fixed-srv.log`; its binary is `/tmp/kvswap-server-fixed`.
  No existing objects were deleted. Restarting it cannot restore missing
  bytes in already-truncated pages; a successful fresh-data test does not
  establish the integrity of old live swap entries.
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
