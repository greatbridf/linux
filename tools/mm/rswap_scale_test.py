#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Scaled rswap run: KV server, remote-only swap, 512M anon mapping.

rswap_run_test.py expects a prepared host: the KV server listening on the
endpoint mm/rswap.c hardcodes, and an rswap device as the only swap device.
This script performs that setup for a large anonymous mapping, runs the
bounded integrity verifier, and then audits the backend directory.  A scaled
run therefore also proves that the backend holds exactly one object per base
page of the mapping, each object the size of a base page: no missing,
duplicate or fallback keys.

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
SERVER_TIMEOUT = 10.0
KV_HOST = "127.0.0.1"
KV_PORT = 6789		# hardcoded in mm/rswap.c


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


def audit_backend(kv_dir, page_size, expected):
    """Every base page stored once, at full page size, and nothing else.

    kvswap_server stores each key as <data_dir>/<2 hex>/<sha256>, so the
    objects sit one directory level below the data directory.
    """
    sizes = {path.name: path.stat().st_size
             for path in kv_dir.rglob("*") if path.is_file()}
    short = [f"{name}={size}" for name, size in sizes.items()
             if size != page_size]
    print(f"Backend objects: {len(sizes)}, expected {expected}")
    if short:
        print(f"FAIL: {len(short)} object(s) not {page_size} bytes: "
              + " ".join(short[:8]), file=sys.stderr)
    if len(sizes) != expected or short:
        print("FAIL: backend does not hold one object per base page",
              file=sys.stderr)
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
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--huge", action="store_true")
    parser.add_argument("--kv-dir", default=None,
                        help="empty backend directory (default: new temp dir)")
    parser.add_argument("--takeover-swap", action="store_true",
                        help="swap off existing devices during the run and "
                             "restore them afterwards")
    parser.add_argument("--keep-bytes", action="store_true",
                        help="keep the backend objects for inspection")
    args = parser.parse_args()
    sys.stdout.reconfigure(line_buffering=True)

    if os.geteuid() != 0:
        parser.error("run as root: needs swap setup and cgroup control")
    if args.size_kib <= 0 or args.rounds <= 0:
        parser.error("size and rounds must be positive")
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
        if len(created) != 1:
            raise RuntimeError("no rswap device in /proc/swaps after "
                               "creating one")
        name, _, device_kib, _ = created[0]
        print(f"Created {name} with {device_kib} KiB of remote swap")
        if device_kib < needed_kib:
            raise RuntimeError(
                f"{name} has {device_kib} KiB but the run needs "
                f"{needed_kib} KiB; raise /sys/module/xswap/parameters/max")
        kv_port = (pathlib.Path("/sys/kernel/debug/rswap") /
                   f"type{name.removeprefix('xswap')}/kv_port")
        if not kv_port.is_file():
            raise RuntimeError(f"{name} has no rswap backend ({kv_port})")
        device = name.removeprefix("xswap")

        command = [sys.executable, str(here / "rswap_run_test.py"),
                   "--binary", args.binary,
                   "--size-kib", str(args.size_kib),
                   "--rounds", str(args.rounds)]
        if args.huge:
            command.append("--huge")
        print("Running:", " ".join(command))
        result = subprocess.run(command, check=False).returncode

        # Each round rewrites the mapping with a fresh seed, so a complete
        # round stores one object per base page and none of them repeat.
        audited = audit_backend(kv_dir, page_size, pages * args.rounds)
        if result:
            print(f"FAIL: verifier exited with {result}", file=sys.stderr)
        elif audited:
            print(f"PASS: {args.size_kib} KiB of anon memory round-tripped "
                  f"through {pages * args.rounds} backend objects")
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
