#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Scaled rswap run: KV server, remote-only swap, 512M anon mapping.

rswap_run_test.py expects a prepared host: the KV server listening on the
endpoint mm/rswap.c defaults to, and an rswap device as the only swap device.
This script performs that setup for a large anonymous mapping, runs the
bounded integrity verifier with a digest manifest, and then audits the
backend directory against that manifest.  A scaled run therefore proves that
the backend holds exactly one object per base page of the mapping, each
object the size of a base page, under exactly the userspace digest: no
missing, duplicate, extra or fallback keys.  A key derived from anything else
(an entry hash, an earlier round's digest) fails the audit.

Two rounds are the default so that swap-slot and key reuse become visible: a
second round must store a fresh object per page, not overwrite the first.

Host state is restored before exit: the rswap device is destroyed, the KV
server is stopped, and every swap device shut down with --takeover-swap is
swapped back in with its original priority.
"""

import argparse
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

CREATE_PATH = pathlib.Path("/sys/kernel/mm/xswap/create")
DESTROY_PATH = pathlib.Path("/sys/kernel/mm/xswap/destroy")
ATTACH_PATH = pathlib.Path("/proc/sys/vm/rswap/attach")
DEBUG_PATH = pathlib.Path("/sys/kernel/debug/rswap")
SERVER_TIMEOUT = 10.0
KV_HOST = "127.0.0.1"
KV_PORT = 6789		# hardcoded in mm/rswap.c
LOOPBACK = ("127.0.0.1", "::1", "localhost")
# Width of one backend key: mm/rswap.c emits RSWAP_HASH_LEN (48) bytes with
# bin2hex(), so 96 hex digits.  The /proc/sys/vm/rswap/attach digest is a
# 32-byte SHA-256 that the core zero extends, so a manifest line can be shorter.
KV_KEY_HEXLEN = 96
# Verifiers exit with this status for a documented skip, and a runner that
# gets a timeout kills the verifier the way it kills the server.
VERIFIER_SKIP = 77
DEFAULT_TIMEOUT = 3600.0


class SkipRun(RuntimeError):
    """The verifier skipped the measurement for a documented reason."""


def read_swaps():
    rows = []
    for line in pathlib.Path("/proc/swaps").read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) < 5:
            continue
        rows.append((fields[0], fields[1], int(fields[2]), int(fields[4])))
    return rows


def rswap_devices():
    return [row for row in read_swaps() if row[0].startswith("xswap")]


def port_open():
    with socket.socket() as probe:
        probe.settimeout(0.2)
        return probe.connect_ex((KV_HOST, KV_PORT)) == 0


def wait_for_server(server):
    deadline = time.monotonic() + SERVER_TIMEOUT
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise RuntimeError(f"KV server exited with {server.returncode}")
        if port_open():
            if server.poll() is not None:
                raise RuntimeError(
                    f"KV server exited with {server.returncode}: "
                    f"{KV_HOST}:{KV_PORT} is taken")
            return
        time.sleep(0.05)
    raise RuntimeError(f"KV server did not listen on {KV_HOST}:{KV_PORT}")


def parse_endpoint(text):
    """Split an rswap endpoint of the form host:port."""
    host, _, port = text.strip().rpartition(":")
    return host.strip("[]"), int(port)


def require_loopback_endpoint(device=None):
    """Refuse to run unless the kernel talks to the server started here.

    The runner owns exactly one loopback HTTP server, so a kernel configured
    for another backend or a remote store would write this run's pages to a
    live backend while the audit looked at an empty local directory.  The
    per-device kv_port is checked too because it is the value the device
    actually resolved.
    """
    backend = (DEBUG_PATH / "backend").read_text().strip()
    host, port = parse_endpoint((DEBUG_PATH / "endpoint").read_text())
    if backend != "http":
        raise RuntimeError(f"kernel backend is {backend!r}; the runner starts an "
                           "HTTP server, so boot with rswap.backend=http")
    if host not in LOOPBACK or port != KV_PORT:
        raise RuntimeError(f"kernel endpoint is {host}:{port}; the runner serves "
                           f"{KV_HOST}:{KV_PORT}, so boot with "
                           f"rswap.host={KV_HOST} rswap.port={KV_PORT}")
    if device is None:
        return
    resolved = (DEBUG_PATH / f"type{device}" / "kv_port").read_text().strip()
    if resolved != str(KV_PORT):
        raise RuntimeError(f"xswap{device} resolved KV port {resolved}, not the "
                           f"{KV_PORT} the runner serves")


def backend_key(line):
    """Backend object name for one digest manifest line."""
    digest = line.strip().lower()
    if (not digest or len(digest) > KV_KEY_HEXLEN or
            any(c not in "0123456789abcdef" for c in digest)):
        raise ValueError(f"malformed digest in manifest: {line!r}")
    return digest.ljust(KV_KEY_HEXLEN, "0")


def expected_keys(manifest, expected):
    """Read the verifier's digest manifest into the set of expected keys."""
    lines = [line for line in pathlib.Path(manifest).read_text().splitlines()
             if line.strip()]
    keys = {backend_key(line) for line in lines}
    if len(lines) != expected or len(keys) != expected:
        raise RuntimeError(f"{manifest} has {len(lines)} digests "
                           f"({len(keys)} distinct), the run needs {expected}")
    return keys


def restore_swap(name, priority):
    """Swap @name back in, reinitializing zram devices through systemd."""
    device = pathlib.Path(name).name
    if device.startswith("zram"):
        # swapoff leaves a zram device without a swap signature; the
        # generator unit recreates it before the .swap unit can be enabled.
        subprocess.run(["systemctl", "start",
                        f"systemd-zram-setup@{device}.service"], check=False)
        subprocess.run(["systemctl", "start", f"dev-{device}.swap"],
                       check=False)
        if any(row[0] == name for row in read_swaps()):
            return
    subprocess.run(["swapon", "-p", str(priority), name], check=True)
    if not any(row[0] == name for row in read_swaps()):
        raise RuntimeError(f"{name} is not back in /proc/swaps after swapon")


def audit_backend(kv_dir, page_size, keys):
    """Every base page stored once under its userspace digest, and nothing else.

    kvswap_server stores each key as <data_dir>/<2 hex>/<key>, so the objects
    sit one directory level below the data directory.  Comparing names, not
    just counting them, is what rejects a key the kernel derived from anything
    other than the digest.
    """
    sizes = {path.name: path.stat().st_size
             for path in kv_dir.rglob("*") if path.is_file()}
    names = set(sizes)
    missing = sorted(keys - names)
    extra = sorted(names - keys)
    short = [f"{name}={size}" for name, size in sorted(sizes.items())
             if size != page_size]
    print(f"Backend objects: {len(names)}, expected {len(keys)}")
    if missing:
        print(f"FAIL: {len(missing)} expected key(s) missing: "
              + " ".join(missing[:8]), file=sys.stderr)
    if extra:
        print(f"FAIL: {len(extra)} object(s) not under a userspace digest: "
              + " ".join(extra[:8]), file=sys.stderr)
    if short:
        print(f"FAIL: {len(short)} object(s) not {page_size} bytes: "
              + " ".join(short[:8]), file=sys.stderr)
    if missing or extra or short:
        print("FAIL: backend does not hold one object per base page under its "
              "userspace digest", file=sys.stderr)
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Scaled rswap integrity run with a backend key audit.")
    here = pathlib.Path(__file__).resolve().parent
    parser.add_argument("--binary", default=str(here / "rswap_test"))
    parser.add_argument("--server", default=str(here / "kvswap_server"))
    parser.add_argument("--size-kib", type=int, default=512 * 1024,
                        help="anonymous mapping size (default: 512 MiB)")
    parser.add_argument("--rounds", type=int, default=2,
                        help="mapping rewrites with a fresh seed (default: 2, "
                             "so slot and key reuse become visible)")
    parser.add_argument("--huge", action="store_true")
    parser.add_argument("--kv-dir", default=None,
                        help="empty backend directory (default: new temp dir)")
    parser.add_argument("--takeover-swap", action="store_true",
                        help="swap off existing devices during the run and "
                             "restore them afterwards")
    parser.add_argument("--keep-bytes", action="store_true",
                        help="keep the backend objects for inspection")
    parser.add_argument("--digests", default=None,
                        help="keep the digest manifest at this path "
                             "(default: temporary, removed afterwards)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"seconds before the verifier is killed "
                             f"(default: {DEFAULT_TIMEOUT:.0f})")
    args = parser.parse_args()
    sys.stdout.reconfigure(line_buffering=True)

    if os.geteuid() != 0:
        parser.error("run as root: needs swap setup and cgroup control")
    if args.size_kib <= 0 or args.rounds <= 0 or args.timeout <= 0:
        parser.error("size, rounds and timeout must be positive")
    page_size = os.sysconf("SC_PAGE_SIZE")
    if args.size_kib * 1024 % page_size:
        parser.error(f"size must be a multiple of {page_size} bytes")
    for option, path, target in (
            ("--binary", args.binary, "rswap_test"),
            ("--server", args.server, "kvswap_server")):
        if not pathlib.Path(path).is_file():
            parser.error(f"missing {path} ({option}); "
                         f"build it with make -C tools/mm {target}")
    if not CREATE_PATH.is_file() or not ATTACH_PATH.is_file():
        parser.error("kernel has no rswap interfaces (CONFIG_RSWAP)")
    try:
        require_loopback_endpoint()
    except (OSError, ValueError, RuntimeError) as error:
        parser.error(str(error))

    active = rswap_devices()
    if active:
        parser.error("destroy active rswap devices first: " + " ".join(
            f"echo {name.removeprefix('xswap')} > {DESTROY_PATH}"
            for name, *_ in active))
    others = [(name, priority) for name, type_, size, priority in read_swaps()
              if not name.startswith("xswap")]
    if port_open():
        parser.error(f"{KV_HOST}:{KV_PORT} is already in use; stop the "
                     "existing KV server first")
    if others and not args.takeover_swap:
        parser.error("rswap must be the only swap device; rerun with "
                     "--takeover-swap to restore " + ", ".join(
                         name for name, _ in others) + " afterwards")

    pages = args.size_kib * 1024 // page_size
    needed_kib = 2 * args.size_kib    # rswap_run_test.py sets memory.swap.max
    if args.kv_dir:
        kv_dir = pathlib.Path(args.kv_dir)
        if kv_dir.exists() and any(kv_dir.iterdir()):
            parser.error(f"{kv_dir} is not empty")
        owned = False
    else:
        kv_dir = pathlib.Path(tempfile.mkdtemp(prefix="rswap-scale-kv-",
                                               dir="/tmp"))
        owned = True
    if args.digests:
        digests = pathlib.Path(args.digests)
        digests_dir = None
    else:
        digests_dir = pathlib.Path(tempfile.mkdtemp(
            prefix="rswap-scale-digests-", dir="/tmp"))
        digests = digests_dir / "digests.txt"
    if digests.exists():
        parser.error(f"{digests} exists; the verifier creates its manifest")
    free = shutil.disk_usage(kv_dir.parent).free
    required = args.size_kib * 1024 * args.rounds * 6 // 5
    if free < required:
        parser.error(f"{kv_dir.parent} needs {required} free bytes for the "
                     f"backend objects, has {free}; use --kv-dir")

    swapped_out = []
    server = None
    device = None
    result = 1
    try:
        for name, priority in others:
            print(f"swapoff {name} (priority {priority})")
            subprocess.run(["swapoff", name], check=True)
            swapped_out.append((name, priority))

        kv_dir.mkdir(parents=True, exist_ok=True)
        server = subprocess.Popen([args.server, "-d", str(kv_dir),
                                   "-p", str(KV_PORT), "-l", KV_HOST])
        wait_for_server(server)
        print(f"KV server on {KV_HOST}:{KV_PORT}, objects in {kv_dir}")

        CREATE_PATH.write_text("rswap 200\n")
        created = rswap_devices()
        # Take ownership of whatever appeared before any other check can
        # raise, so the device is always destroyed on the way out.
        if created:
            device = created[0][0].removeprefix("xswap")
        if len(created) != 1:
            raise RuntimeError("expected one new rswap device in "
                               f"/proc/swaps, found {len(created)}")
        name, _, device_kib, _ = created[0]
        print(f"Created {name} with {device_kib} KiB of remote swap")
        if device_kib < needed_kib:
            raise RuntimeError(
                f"{name} has {device_kib} KiB but the run needs "
                f"{needed_kib} KiB; raise /sys/module/xswap/parameters/max")
        require_loopback_endpoint(device)

        command = [sys.executable, str(here / "rswap_run_test.py"),
                   "--binary", args.binary,
                   "--size-kib", str(args.size_kib),
                   "--rounds", str(args.rounds),
                   "--digests", str(digests),
                   "--timeout", str(args.timeout)]
        if args.huge:
            command.append("--huge")
        print("Running:", " ".join(command))
        try:
            result = subprocess.run(command, check=False,
                                    timeout=args.timeout + SERVER_TIMEOUT).returncode
        except subprocess.TimeoutExpired:
            print(f"FAIL: verifier killed after {args.timeout}s",
                  file=sys.stderr)
            result = 1

        if result == VERIFIER_SKIP:
            print(f"SKIP: verifier reported a documented skip (exit {result})")
        else:
            # Each round rewrites the mapping with a fresh seed, so a complete
            # round stores one object per base page and none of them repeat.
            expected = expected_keys(digests, pages * args.rounds)
            audited = audit_backend(kv_dir, page_size, expected)
            if result:
                print(f"FAIL: verifier exited with {result}", file=sys.stderr)
            elif audited:
                print(f"PASS: {args.size_kib} KiB of anon memory round-tripped "
                      f"through {len(expected)} backend objects")
            result = result or (0 if audited else 1)
    finally:
        if device is not None:
            try:
                DESTROY_PATH.write_text(device + "\n")
            except OSError as error:
                print(f"FAIL: cannot destroy xswap{device}: {error}",
                      file=sys.stderr)
                result = result or 1
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=SERVER_TIMEOUT)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
        if digests_dir is not None:
            shutil.rmtree(digests_dir, ignore_errors=True)
        elif digests.exists():
            print(f"Kept digest manifest in {digests}")
        if not args.keep_bytes:
            shutil.rmtree(kv_dir, ignore_errors=True)
        elif owned:
            print(f"Kept backend objects in {kv_dir}")
        for name, priority in reversed(swapped_out):
            try:
                restore_swap(name, priority)
            except (OSError, subprocess.CalledProcessError,
                    RuntimeError) as error:
                print(f"FAIL: cannot restore swap on {name}: {error}; "
                      f"restore it by hand", file=sys.stderr)
                result = result or 1
            else:
                print(f"restored swap on {name} (priority {priority})")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
