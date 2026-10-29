#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run integrity verification in a bounded cgroup, leaving the host unchanged."""

import argparse
import os
import pathlib
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=str(
        pathlib.Path(__file__).with_name("rswap_test")))
    parser.add_argument("--size-kib", type=int, default=1024)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--huge", action="store_true")
    parser.add_argument("--disable-zswap", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root to create a test cgroup")
    if args.size_kib <= 0 or args.rounds <= 0:
        parser.error("size and rounds must be positive")
    swap_lines = pathlib.Path("/proc/swaps").read_text().splitlines()[1:]
    if not swap_lines or any(not line.startswith("xswap") for line in swap_lines):
        parser.error("requires only remote xswap devices in /proc/swaps")
    if not pathlib.Path("/sys/kernel/debug/rswap").is_dir():
        parser.error("no remote-swap debugfs directory")
    for line in swap_lines:
        swap_type = line.split()[0].removeprefix("xswap")
        port = pathlib.Path("/sys/kernel/debug/rswap") / f"type{swap_type}/kv_port"
        if not port.is_file():
            parser.error("every active swap device must have an rswap backend")

    cg = pathlib.Path(tempfile.mkdtemp(prefix="rswap-integrity-",
                                     dir="/sys/fs/cgroup"))
    try:
        limit = max(64 * 1024 * 1024, args.size_kib * 2048)
        (cg / "memory.max").write_text(str(limit))
        (cg / "memory.swap.max").write_text(str(limit))
        if args.disable_zswap:
            (cg / "memory.zswap.max").write_text("0")
        # The shell enters the cgroup before exec, charging the test correctly.
        command = ["sh", "-c",
                   'printf "%s" "$$" > "$1/cgroup.procs"; shift; exec "$@"',
                   "rswap-test", str(cg), args.binary, str(args.size_kib),
                   str(args.rounds), "huge" if args.huge else "base",
                   str(cg / "memory.reclaim")]
        result = subprocess.run(command, check=False)
        print("Remaining test swap bytes:",
              (cg / "memory.swap.current").read_text().strip())
        return result.returncode
    finally:
        cg.rmdir()


if __name__ == "__main__":
    raise SystemExit(main())
