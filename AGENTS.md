# Remote Swap (rswap) Agent Guide

This file applies to the whole repository. It records the rswap-specific
architecture, invariants, interfaces, test workflow, and kernel contribution
rules that future coding agents must preserve.

## Non-Negotiable Invariant

**Never calculate or derive an rswap page key from a swap entry in the
kernel.**

User space hashes page contents and supplies the SHA-256 digest. The kernel
must not run a hash function over `swp_entry_t`, the page contents, or any
other kernel-derived value to create a key.

Writeout behavior is strict:

1. Read the userspace digest from `page_ext`.
2. Store that digest in the rswap device table at the page's swap offset.
3. Use only that stored digest as the HTTP KV key.

If no digest is attached, writeout fails with `-ENODATA`. Do not add a
fallback key. Swapin reads only the per-entry table and fails with `-ENOENT`
if no digest was stored.

An earlier implementation incorrectly hashed swap entries. That behavior was
removed in commit `e254942f9d5ac ("mm: rswap: use userspace provided hash
only")` and must not return.

## Project Purpose

rswap is a fileless xswap backend that stores swap pages in an external HTTP
key-value store. Each base page is stored under a SHA-256 hex key supplied by
user space for that page.

The current backend is deliberately simple:

- HTTP/1.0 over a hardcoded loopback endpoint, `127.0.0.1:6789`.
- One HTTP request per base page.
- A userspace `kvswap_server` stores one file per key.
- No network authentication, payload encryption, or server persistence
  guarantees beyond the backend implementation.
- eBPF integration is postponed and is not part of the active build.

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

### Kernel Entry Point

`mm/rswap.c` is the main implementation. It contains:

- kernel socket and HTTP request/response handling;
- swap page I/O through the `swap_ops` interface;
- the `/proc/sys/vm/rswap/attach` sysctl;
- page_ext digest access;
- per-device swap-offset hash storage;
- debugfs per-device port reporting.

The RSWAP Kconfig option is defined in `mm/Kconfig` and depends on:

- `XSWAP`
- `INET`
- `SYSCTL`

It selects `PAGE_EXTENSION` and `CRYPTO_LIB_SHA256`.

### Page-Ext Stage

Before writeout, a page's userspace digest lives in page_ext:

```text
struct rswap_page_ext {
        u8 hash[32];
        bool valid;
};
```

The page-ext client is registered in `mm/page_ext.c`, declared in
`include/linux/page_ext.h`, and selected by `CONFIG_RSWAP`.

Access to the page digest is serialized by `rswap_hash_lock`, a global
spinlock for the short protected copy. Page-ext metadata is not assumed to
stay with one physical page forever:

- `rswap_page_ext_copy()` preserves the digest during folio migration.
- `rswap_page_ext_reset()` clears stale metadata when a page is freed.

`mm/migrate.c` invokes the copy hook. `mm/page_alloc.c` invokes the reset
hook on normal and hardware-poisoned page free paths.

### Per-Device Entry Table

page_ext alone is insufficient on swapin. A swap-cache page may have been
evicted, so its original `struct page` and page-ext data may no longer exist.

`struct swap_info_struct` therefore owns an rswap table:

```text
struct rswap_hash_entry {
        u8 hash[32];
        u8 valid;
};
```

The table is indexed directly by `swp_offset(entry)` and is allocated with
`kvcalloc(si->max, sizeof(*si->rswap_hashes), GFP_KERNEL)`. The valid byte
makes the table 33 bytes per swap slot for the current layout.

Writeout:

1. Resolve each base page and its precise swap entry.
2. Read the page-ext digest.
3. Return `-ENODATA` if the page has no attached digest.
4. Copy the digest into `si->rswap_hashes[swp_offset(entry)]`.
5. Publish validity with release semantics.
6. POST the page using the stored digest as the key.

Swapin:

1. Resolve the swap device from the entry.
2. Acquire-load the table slot validity.
3. Return `-ENOENT` if no digest is stored.
4. GET the page using the stored digest as the key.

Slot release calls `rswap_hash_invalidate()` from `mm/swapfile.c`, clearing
table validity before the slot is reused. Device teardown frees the full
table.

The `valid` flag uses release/acquire ordering so a reader cannot observe a
valid slot before the digest contents are visible.

### Data Flow

```text
user mmap
  -> userspace SHA-256 per base page
  -> /proc/sys/vm/rswap/attach
  -> page_ext hash + valid
  -> reclaim / swapout
  -> device table[swp_offset] = page_ext hash
  -> HTTP POST /v1/folios/<hash>/write

swap fault
  -> device table[swp_offset]
  -> HTTP GET /v1/folios/<hash>/read
  -> page is filled and unmapped metadata may disappear
  -> swap slot release invalidates the table entry
```

## Relevant Files

- `mm/rswap.c`: rswap backend, sysctl, page-ext and table implementation.
- `mm/rswap.h`: rswap lifecycle declarations and no-op configuration stubs.
- `include/linux/page_ext.h`: page-ext client declarations and lifecycle hooks.
- `mm/page_ext.c`: page-ext client registration.
- `include/linux/swap.h`: per-device hash table pointer in
  `struct swap_info_struct`.
- `mm/page_alloc.c`: clear page-ext digest on page free.
- `mm/migrate.c`: copy page-ext digest on migration.
- `mm/swapfile.c`: xswap device creation/destruction and slot-release hash
  invalidation.
- `Documentation/admin-guide/sysctl/vm.rst`: sysctl ABI documentation.
- `rswap-userspace-demos/`: mmap, userspace hashing, and sysctl attach tool.
- `tools/mm/kvswap_server.c`: HTTP KV backend.
- `tools/mm/rswap_test.c`: bounded integrity verifier that attaches page
  hashes before reclaim.
- `tools/mm/rswap_run_test.py`: cgroup-based live test runner.
- `tools/mm/rswap_backend_test.py`: source-level backend and table regressions.
- `tools/mm/kvswap_test.py`: HTTP protocol regression tests.

## Interfaces and Operations

Create an rswap device:

```sh
echo "rswap 200" > /sys/kernel/mm/xswap/create
```

Destroy it by swap type:

```sh
echo 0 > /sys/kernel/mm/xswap/destroy
```

The kernel hardcodes the KV server address as `127.0.0.1:6789`.

Start the server:

```sh
tools/mm/kvswap_server -d /tmp/rswap-kv -p 6789
```

The server endpoints are:

```text
POST /v1/folios/<sha256>/write
GET  /v1/folios/<sha256>/read
```

Per-device KV port information is exposed through debugfs:

```text
/sys/kernel/debug/rswap/type<N>/kv_port
```

## Build and Verification

Build the kernel and relevant objects:

```sh
make O=build LLVM=1 -j"$(nproc)" W=1 \
    mm/rswap.o mm/swapfile.o mm/page_alloc.o mm/migrate.o Image
```

Build userspace tools:

```sh
make -C rswap-userspace-demos user
make -C tools/mm kvswap_server rswap_test
```

Source and protocol tests:

```sh
python3 tools/mm/rswap_backend_test.py
python3 tools/mm/kvswap_test.py
```

Live integrity test, with rswap as the only active swap device:

```sh
sudo python3 tools/mm/rswap_run_test.py --size-kib 8192 --rounds 5
```

The verifier now attaches userspace hashes before each round. This update is
required because unattached pages intentionally fail writeout.

For manual live testing, stop zram swap before creating the remote-only
configuration:

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

The no-fallback design has been tested live on ARM64 with 16 KiB base pages:

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
- Backend source regressions and all 11 KV protocol tests passed.

Expected `-ENODATA`/`-61` kernel messages occur during deliberate tests of
writeout without an attached digest. They are not evidence of a fallback
path.

## Known Limitations

- A page intended for remote swap must have a userspace digest attached
  before reclaim. If it does not, writeout fails and the page stays resident,
  which can eventually lead to OOM under pressure.
- The caller must update the digest after modifying page contents.
- The device table is in memory and is not persistent across swapoff,
  device destruction, or reboot. Remote server objects may remain.
- The current digest is an integrity input supplied by user space. The kernel
  does not independently recompute or verify it against page contents.
- The KV endpoint is hardcoded to loopback and has no authentication.
- The single-threaded KV server and one-request-per-page design are for
  testing, not production throughput.
- There is no active eBPF integration.

## eBPF Status

The eBPF prototype is postponed. `rswap-userspace-demos/page_hash_kern.bpf.c`
and `page_hash_test_mod.c` may remain as experimental source, but the active
Makefile builds only the userspace sysctl tool. Do not re-enable eBPF without
an explicit design change.

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
