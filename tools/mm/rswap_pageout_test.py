#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Measure one whole-mapping MADV_PAGEOUT (512 MiB by default).

The backend must already be reachable. --takeover-swap temporarily replaces
other swap devices with rswap. Digests and trace evidence stay in --output;
backend objects are retained for auditing. This test never uses memory.reclaim.
Fprobe events in a private trace instance measure batch size and overlap.
Success requires every page to have a swap PTE and a successful backend write;
mincore residency is reported separately because swap cache can retain pages.
"""

import argparse
import collections
import contextlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

from rswap_scale_test import read_swaps, restore_swap

DEBUG = pathlib.Path('/sys/kernel/debug/rswap')
XSWAP = pathlib.Path('/sys/kernel/mm/xswap')
TRACE = pathlib.Path('/sys/kernel/tracing')
MADV_PAGEOUT = 21


def write_control(path, value):
    # tracefs dynamic_events does not accept O_APPEND.
    fd = os.open(path, os.O_WRONLY)
    try:
        data = (value + '\n').encode()
        if os.write(fd, data) != len(data):
            raise RuntimeError(f'short write to {path}')
    finally:
        os.close(fd)


def counters():
    return {key: int(value) for key, value in
            (line.split() for line in (DEBUG / 'stats').read_text().splitlines())
            if value.isdecimal()}


@contextlib.contextmanager
def batch_trace():
    group = f'rswap_pageout_{os.getpid()}'
    instance = TRACE / 'instances' / group
    definitions = {
        'batch_enter': 'rswap_flush_batch nr=$arg4:u32 rw=$arg5:s32',
        'batch_exit': 'rswap_flush_batch%return ret=$retval:s32 rw=$arg5:s32',
        'advice_enter': 'do_madvise start=$arg2:x64 len=$arg3:u64 behavior=$arg4:s32',
        'advice_exit': 'do_madvise%return ret=$retval:s32 behavior=$arg4:s32',
    }
    created = []
    instance.mkdir()
    try:
        write_control(instance / 'tracing_on', '0')
        write_control(instance / 'trace_clock', 'global')
        write_control(instance / 'buffer_size_kb', '2048')
        for name, definition in definitions.items():
            write_control(TRACE / 'dynamic_events',
                          f'f:{group}/{name} {definition}')
            created.append(name)
            event = instance / 'events' / group / name
            write_control(event / 'filter',
                          'rw == 1' if name.startswith('batch') else
                          f'behavior == {MADV_PAGEOUT}')
            write_control(event / 'enable', '1')
        yield instance
    finally:
        write_control(instance / 'tracing_on', '0')
        for name in reversed(created):
            write_control(instance / 'events' / group / name / 'enable', '0')
        instance.rmdir()
        for name in reversed(created):
            write_control(TRACE / 'dynamic_events', f'-:{group}/{name}')


def trace_result(text, pid, size, address):
    pattern = re.compile(r'-(\d+)\s+\[\d+\].*?\s(\d+\.\d+): '
                         r'(batch_enter|batch_exit|advice_enter|advice_exit): (.*)')
    active = {}
    histogram = collections.Counter()
    tids = set()
    peak = completed = pages = calls = returns = 0
    duration = 0.0
    syscall_start = syscall_end = None
    first_batch_start = last_batch_end = None
    for line in text.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        tid, timestamp, event, payload = match.groups()
        tid, timestamp = int(tid), float(timestamp)
        fields = {key: int(value, 0) for key, value in
                  re.findall(r'(\w+)=(-?(?:0x[0-9a-f]+|\d+))', payload)}
        if event == 'advice_enter' and tid == pid:
            calls += 1
            syscall_start = timestamp
            if fields['len'] != size or fields['start'] != address:
                raise RuntimeError('MADV_PAGEOUT did not cover the whole mapping')
        elif event == 'advice_exit' and tid == pid:
            returns += 1
            syscall_end = timestamp
            if fields['ret']:
                raise RuntimeError('MADV_PAGEOUT returned an error')
        elif event == 'batch_enter':
            if tid in active:
                raise RuntimeError('nested batch or missing return event')
            active[tid] = timestamp
            if first_batch_start is None:
                first_batch_start = timestamp
            tids.add(tid)
            histogram[fields['nr']] += 1
            pages += fields['nr']
            peak = max(peak, len(active))
        elif event == 'batch_exit':
            if tid not in active or fields['ret']:
                raise RuntimeError('unmatched or failed batch return')
            duration += timestamp - active.pop(tid)
            completed += 1
            last_batch_end = timestamp
    if calls != 1 or returns != 1 or active:
        raise RuntimeError('incomplete trace or unexpected MADV_PAGEOUT count')
    if not completed or first_batch_start < syscall_start or last_batch_end > syscall_end:
        raise RuntimeError('no batches, or writeout outside the measured syscall')
    return {'madv_pageout_calls': calls, 'pages': pages, 'batches': completed,
            'batch_histogram': dict(sorted(histogram.items())),
            'peak_inflight_batches': peak, 'writer_tids': sorted(tids),
            'batch_seconds_sum': duration,
            'syscall_seconds_trace': syscall_end - syscall_start,
            'all_batches_finished_before_return': True}


def fields(line):
    return {key: int(value, 0) for key, value in
            (word.split('=') for word in line.split()[1:])}


def run_test(args, output, instance, cg):
    command = ['sh', '-c',
               'printf "%s" "$$" > "$1/cgroup.procs"; shift; exec "$@"',
               'rswap-pageout', str(cg), str(pathlib.Path(args.binary).resolve()),
               str(args.size_kib), 'huge' if args.huge else 'base',
               str(output / 'digests.txt')]
    proc = subprocess.Popen(command, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1)
    before = after = ready = pageout = evidence = None
    log = []
    try:
        for line in proc.stdout:
            print(line, end='', flush=True)
            log.append(line)
            if line.startswith('READY '):
                ready = fields(line)
                before = counters()
                write_control(instance / 'tracing_on', '1')
                proc.stdin.write('G')
                proc.stdin.flush()
            elif line.startswith('PAGEOUT '):
                pageout = fields(line)
                write_control(instance / 'tracing_on', '0')
                after = counters()
                evidence = (instance / 'trace').read_text()
                (output / 'trace.txt').write_text(evidence)
                for path in (instance / 'per_cpu').glob('cpu*/stats'):
                    stats = path.read_text()
                    (output / f'{path.parent.name}-trace-stats.txt').write_text(stats)
                    for row in stats.splitlines():
                        key, value = row.split(':', 1)
                        if key.strip() in ('overrun', 'commit overrun', 'dropped events') and int(value):
                            raise RuntimeError('trace buffer lost events')
                proc.stdin.write('G')
                proc.stdin.flush()
        ret = proc.wait()
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait()
        proc.stdin.close()
        proc.stdout.close()
        (output / 'verifier.log').write_text(''.join(log))
    if not ready or not pageout or evidence is None:
        raise RuntimeError(f'verifier did not finish pageout (exit {ret})')
    verified = counters()
    delta = {key: after[key] - before[key] for key in after
             if key not in ('batch_max',) and not key.endswith(('_avg_ns', '_max_ns'))}
    result = {'kernel': os.uname().release, 'backend': (DEBUG / 'backend').read_text().strip(),
              'size_kib': args.size_kib, 'huge': args.huge, 'ready': ready,
              'pageout': pageout, 'before': before, 'after_pageout': after,
              'after_verify': verified,
              'delta_pageout': delta, 'verifier_exit': ret,
              'memory_events': (cg / 'memory.events').read_text(),
              'remaining_swap_bytes': int((cg / 'memory.swap.current').read_text())}
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    traced = trace_result(evidence, ready['pid'], ready['bytes'], ready['address'])
    result['trace'] = traced
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f"PAGEOUT: {pageout['ns'] / 1e9:.3f}s, "
          f"{pageout['swapped']}/{pageout['pages']} swap PTEs, "
          f"{pageout['nonresident']} nonresident pages")
    print('Batch histogram (pages: calls):', traced['batch_histogram'])
    print('Peak simultaneous backend batches:', traced['peak_inflight_batches'])
    print('Writer TIDs:', traced['writer_tids'])
    print('Writeout counters:', delta)
    if ret or pageout['swapped'] != pageout['pages'] or pageout['present']:
        raise RuntimeError('verifier failed or single-call pageout was incomplete')
    if traced['pages'] != pageout['pages'] or traced['pages'] != delta['written_pages'] or traced['batches'] != delta['written_batches']:
        raise RuntimeError('trace, page count, and counters disagree')
    if max(traced['batch_histogram']) > before['batch_max']:
        raise RuntimeError('backend exceeded batch_max')
    if delta['written_errors'] or delta['read_pages'] or result['remaining_swap_bytes']:
        raise RuntimeError('unexpected I/O errors, reads during pageout, or leftover swap')
    if verified['read_errors'] != after['read_errors']:
        raise RuntimeError('swapin errors during data verification')
    if pageout['pages'] > before['batch_max'] and max(traced['batch_histogram']) <= 1:
        raise RuntimeError('writeout did not batch pages')
    print('PASS: whole-mapping pageout, batched writeout, trace and data integrity')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default=str(pathlib.Path(__file__).with_suffix('')))
    parser.add_argument('--size-kib', type=int, default=512 * 1024)
    parser.add_argument('--huge', action='store_true')
    parser.add_argument('--takeover-swap', action='store_true')
    parser.add_argument('--output', type=pathlib.Path,
                        help='new directory for results, traces and digest manifest')
    args = parser.parse_args()
    sys.stdout.reconfigure(line_buffering=True)
    if os.geteuid() or args.size_kib <= 0 or args.size_kib * 1024 % os.sysconf('SC_PAGE_SIZE'):
        parser.error('requires root and a positive native-page-aligned size')
    if not pathlib.Path(args.binary).is_file():
        parser.error('build with make -C tools/mm rswap_pageout_test')
    if not (DEBUG / 'stats').exists() or not (TRACE / 'dynamic_events').exists():
        parser.error('requires rswap debugfs and CONFIG_FPROBE_EVENTS tracefs')
    original = read_swaps()
    others = [row for row in original if not row[0].startswith('xswap')]
    if others and not args.takeover_swap:
        parser.error('use --takeover-swap to temporarily replace other swap devices')
    for name, *_ in original:
        if name.startswith('xswap') and not (DEBUG / f'type{name[5:]}' / 'kv_port').exists():
            parser.error('active xswap device is not rswap')
    output = args.output.resolve() if args.output else pathlib.Path(tempfile.mkdtemp(prefix='rswap-pageout-'))
    if args.output:
        output.mkdir(parents=True, exist_ok=False)
    print('Results:', output)
    disabled = []
    device = None
    cg = None
    try:
        with batch_trace() as instance:
            for name, _, _, priority in others:
                subprocess.run(['swapoff', name], check=True)
                disabled.append((name, priority))
            if not read_swaps():
                (XSWAP / 'create').write_text('rswap 200\n')
                devices = read_swaps()
                if len(devices) != 1 or not devices[0][0].startswith('xswap'):
                    raise RuntimeError('could not identify created rswap device')
                device = devices[0][0][5:]
            if sum(row[2] for row in read_swaps()) < args.size_kib:
                raise RuntimeError('insufficient remote swap capacity')
            cg = pathlib.Path(tempfile.mkdtemp(prefix='rswap-pageout-', dir='/sys/fs/cgroup'))
            limit = max(64 * 1024 * 1024, args.size_kib * 2048)
            (cg / 'memory.max').write_text(str(limit))
            (cg / 'memory.swap.max').write_text(str(limit))
            (cg / 'memory.zswap.max').write_text('0')
            run_test(args, output, instance, cg)
    finally:
        # Attempt every restoration step even if one fails.
        errors = []
        actions = []
        if cg is not None:
            actions.append(cg.rmdir)
        if device is not None:
            actions.append(lambda: (XSWAP / 'destroy').write_text(device + '\n'))
        for name, priority in reversed(disabled):
            actions.append(lambda n=name, p=priority: restore_swap(n, p))
        for action in actions:
            try:
                action()
            except Exception as error:
                errors.append(str(error))
        if read_swaps() != original:
            errors.append('original swap configuration not restored')
        if errors:
            raise RuntimeError('; '.join(errors))
        print('Restored original swap configuration and removed test tracing/cgroup')
        print('Backend objects retained; expected keys are in', output / 'digests.txt')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
