#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Measure cold remote swapin using WILLNEED or concurrent page faults.

The 512 MiB mapping is fully evicted before measurement. Modes are a
WILLNEED call on each worker's disjoint range, or one load per page.
Backend read batches and overlap are measured with temporary fprobe events.
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
import time

from rswap_scale_test import read_swaps, restore_swap

DEBUG = pathlib.Path('/sys/kernel/debug/rswap')
XSWAP = pathlib.Path('/sys/kernel/mm/xswap')
TRACE = pathlib.Path('/sys/kernel/tracing')
MADV_WILLNEED = 3


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


def idle_counters():
    """Read the counters once no read batch is in flight any more.

    A worker releases its slot right after the completion callback marked the
    folios uptodate, so the last batch of the run can still be visible for a
    moment after mincore() reported the whole mapping loaded.  Wait that out
    instead of sampling a gauge that is legitimately one off.
    """
    deadline = time.monotonic() + 5
    while True:
        stats = counters()
        if not stats['read_inflight'] or time.monotonic() > deadline:
            return stats
        time.sleep(0.02)


@contextlib.contextmanager
def batch_trace():
    group = f'rswap_swapin_{os.getpid()}'
    instance = TRACE / 'instances' / group
    load = f"rswap_{(DEBUG / 'backend').read_text().strip()}_load"
    definitions = {
        'batch_enter': f'{load} nr=$arg2:u32',
        'batch_exit': f'{load}%return ret=$retval:s32',
        'advice_enter': 'do_madvise start=$arg2:x64 len=$arg3:u64 behavior=$arg4:s32',
        'advice_exit': 'do_madvise%return ret=$retval:s32 behavior=$arg4:s32',
    }
    created = []
    instance.mkdir()
    try:
        write_control(instance / 'tracing_on', '0')
        write_control(instance / 'trace_clock', 'global')
        write_control(instance / 'buffer_size_kb', '8192')
        for name, definition in definitions.items():
            write_control(TRACE / 'dynamic_events',
                          f'f:{group}/{name} {definition}')
            created.append(name)
            event = instance / 'events' / group / name
            if name.startswith('advice'):
                write_control(event / 'filter',
                              f'behavior == {MADV_WILLNEED}')
            write_control(event / 'enable', '1')
        yield instance
    finally:
        write_control(instance / 'tracing_on', '0')
        for name in reversed(created):
            write_control(instance / 'events' / group / name / 'enable', '0')
        instance.rmdir()
        for name in reversed(created):
            write_control(TRACE / 'dynamic_events', f'-:{group}/{name}')


def percentile(values, percent):
    values = sorted(values)
    return values[min(len(values) - 1, (len(values) * percent + 99) // 100 - 1)]


def trace_result(text, ready):
    """Pair batch and advice entry/return events per thread.

    An asynchronous backend moves a read batch on a worker thread, so the
    batches of one WILLNEED caller are neither on its thread nor inside its
    advice window.  What still holds is the per-thread pairing of every entry
    with its return, and that the WILLNEED calls cover the mapping exactly.
    """
    pattern = re.compile(r'-(\d+)\s+\[\d+\].*?\s(\d+\.\d+): '
                         r'(batch_enter|batch_exit|advice_enter|advice_exit): (.*)')
    active = {}
    advice = {}
    ranges = []
    histogram = collections.Counter()
    durations = []
    tids = set()
    peak = pages = returns = 0
    for line in text.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        tid, timestamp, event, payload = match.groups()
        tid, timestamp = int(tid), float(timestamp)
        fields = {key: int(value, 0) for key, value in
                  re.findall(r'(\w+)=(-?(?:0x[0-9a-f]+|\d+))', payload)}
        if event == 'advice_enter':
            if tid in advice:
                raise RuntimeError('nested advice or missing return event')
            advice[tid] = timestamp
            ranges.append((fields['start'], fields['len']))
        elif event == 'advice_exit':
            if tid not in advice or fields['ret']:
                raise RuntimeError('unmatched or failed WILLNEED return')
            advice.pop(tid)
            returns += 1
        elif event == 'batch_enter':
            if tid in active:
                raise RuntimeError('nested batch or missing return event')
            active[tid] = timestamp
            tids.add(tid)
            histogram[fields['nr']] += 1
            pages += fields['nr']
            peak = max(peak, len(active))
        elif event == 'batch_exit':
            if tid not in active or fields['ret']:
                raise RuntimeError('unmatched or failed read batch')
            durations.append(timestamp - active.pop(tid))
    if active or advice or not durations:
        raise RuntimeError('incomplete read trace')
    if ready['willneed']:
        chunk = ready['bytes'] // ready['workers']
        expected = [(ready['address'] + i * chunk, chunk)
                    for i in range(ready['workers'])]
        if sorted(ranges) != expected or returns != ready['workers']:
            raise RuntimeError('WILLNEED ranges do not partition the mapping')
    elif ranges or returns:
        raise RuntimeError('unexpected WILLNEED in fault mode')
    return {'pages': pages, 'batches': len(durations),
            'batch_histogram': dict(sorted(histogram.items())),
            'peak_inflight_batches': peak, 'reader_tids': sorted(tids),
            'willneed_calls': returns, 'batch_seconds_sum': sum(durations),
            'batch_latency_ms': {'p50': percentile(durations, 50) * 1000,
                                 'p95': percentile(durations, 95) * 1000,
                                 'p99': percentile(durations, 99) * 1000,
                                 'max': max(durations) * 1000}}


def fields(line):
    return {key: int(value, 0) for key, value in
            (word.split('=') for word in line.split()[1:])}


def run_test(args, output, instance, cg):
    command = ['sh', '-c',
               'printf "%s" "$$" > "$1/cgroup.procs"; shift; exec "$@"',
               'rswap-swapin', str(cg), str(pathlib.Path(args.binary).resolve()),
               str(args.size_kib), args.mode, str(args.workers),
               str(output / 'digests.txt'), str(cg / 'memory.reclaim')]
    proc = subprocess.Popen(command, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1)
    before = after = ready = cold = submitted = loaded = verify = evidence = None
    log = []
    try:
        for line in proc.stdout:
            print(line, end='', flush=True)
            log.append(line)
            if line.startswith('COLD '):
                cold = fields(line)
            elif line.startswith('READY '):
                ready = fields(line)
                before = counters()
                write_control(instance / 'tracing_on', '1')
                proc.stdin.write('G')
                proc.stdin.flush()
            elif line.startswith('SUBMITTED '):
                submitted = fields(line)
            elif line.startswith('LOADED '):
                if submitted is None:
                    raise RuntimeError('LOADED before SUBMITTED')
                loaded = fields(line)
                write_control(instance / 'tracing_on', '0')
                after = idle_counters()
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
            elif line.startswith('VERIFY '):
                verify = fields(line)
        ret = proc.wait()
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait()
        proc.stdin.close()
        proc.stdout.close()
        (output / 'verifier.log').write_text(''.join(log))
    if not ready or not submitted or not loaded or not cold or evidence is None:
        raise RuntimeError(f'verifier did not finish swapin (exit {ret})')
    verified = counters()
    delta = {key: after[key] - before[key] for key in after
             if key not in ('batch_max',) and not key.endswith(('_avg_ns', '_max_ns'))}
    result = {'kernel': os.uname().release, 'backend': (DEBUG / 'backend').read_text().strip(),
              'size_kib': args.size_kib, 'mode': args.mode, 'workers': args.workers,
              'ready': ready, 'cold': cold, 'submitted': submitted, 'loaded': loaded,
              'verify': verify,
              'before': before, 'after_load': after, 'after_verify': verified,
              'delta_load': delta, 'verifier_exit': ret,
              'memory_events': (cg / 'memory.events').read_text(),
              'remaining_swap_bytes': int((cg / 'memory.swap.current').read_text())}
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    traced = trace_result(evidence, ready)
    result['trace'] = traced
    result['payload_mib_s'] = ready['bytes'] / (1024 * 1024) / (loaded['ns'] / 1e9)
    result['submit_mib_s'] = (ready['bytes'] / (1024 * 1024) /
                              (max(submitted['ns'], 1) / 1e9))
    result['completion_tail_s'] = (loaded['ns'] - submitted['ns']) / 1e9
    result['read_peak_inflight'] = after['read_peak_inflight']
    result['read_fallbacks'] = delta['read_fallbacks']
    result['read_submits'] = delta['read_submits']
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f"SUBMIT: {submitted['ns'] / 1e9:.3f}s, {result['submit_mib_s']:.3f} MiB/s, "
          f"completion tail {result['completion_tail_s']:.3f}s")
    print(f"LOAD: {loaded['ns'] / 1e9:.3f}s, {result['payload_mib_s']:.3f} MiB/s, "
          f"{loaded['nonresident']} nonresident pages remaining")
    print('Batch histogram (pages: calls):', traced['batch_histogram'])
    print('Peak simultaneous read batches:', traced['peak_inflight_batches'],
          '(debugfs read_peak_inflight', after['read_peak_inflight'], ')')
    print('Read submits:', delta['read_submits'], 'inline fallbacks:', delta['read_fallbacks'])
    print('Batch latency ms:', traced['batch_latency_ms'])
    print('Load counters:', delta)
    if ret or loaded['nonresident'] or cold['nonresident'] != cold['pages']:
        raise RuntimeError('incomplete eviction, swapin, or corrupt data')
    if after['read_inflight']:
        raise RuntimeError(f"{after['read_inflight']} read batch(es) still in flight "
                           'after the mapping finished loading')
    if args.mode == 'willneed' and after['read_peak_inflight'] < 1:
        raise RuntimeError('WILLNEED never had a read batch in flight')
    if traced['pages'] != ready['pages'] or traced['pages'] != delta['read_pages'] or traced['batches'] != delta['read_batches']:
        raise RuntimeError('trace, page count, and counters disagree')
    if delta['read_pages'] != ready['pages']:
        raise RuntimeError('swapin did not read exactly the mapping')
    if delta['read_bytes'] != ready['bytes'] or max(traced['batch_histogram']) > before['batch_max']:
        raise RuntimeError('wrong byte count or backend exceeded batch_max')
    if delta['read_errors'] or delta['written_pages']:
        raise RuntimeError('unexpected I/O errors or writes during swapin')
    if result['remaining_swap_bytes']:
        print('Cgroup swap charge before device teardown:', result['remaining_swap_bytes'])
    if verified['read_pages'] != after['read_pages'] or verified['read_errors'] != after['read_errors']:
        raise RuntimeError('verification required additional remote reads')
    if not verify or verify['mismatches']:
        raise RuntimeError('data verification failed')
    print('PASS: cold swapin, traced batches/concurrency, and data integrity')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default=str(pathlib.Path(__file__).with_suffix('')))
    parser.add_argument('--size-kib', type=int, default=512 * 1024)
    parser.add_argument('--mode', choices=('willneed', 'fault'), default='willneed')
    parser.add_argument('--workers', type=int, default=1)
    parser.add_argument('--takeover-swap', action='store_true')
    parser.add_argument('--output', type=pathlib.Path,
                        help='new directory for results, traces and digest manifest')
    args = parser.parse_args()
    sys.stdout.reconfigure(line_buffering=True)
    if os.geteuid() or args.size_kib <= 0 or args.size_kib * 1024 % os.sysconf('SC_PAGE_SIZE'):
        parser.error('requires root and a positive native-page-aligned size')
    if not pathlib.Path(args.binary).is_file():
        parser.error('build with make -C tools/mm rswap_swapin_test')
    if not (DEBUG / 'stats').exists() or not (TRACE / 'dynamic_events').exists():
        parser.error('requires rswap debugfs and CONFIG_FPROBE_EVENTS tracefs')
    pages = args.size_kib * 1024 // os.sysconf('SC_PAGE_SIZE')
    if not 1 <= args.workers <= 32 or pages % args.workers:
        parser.error('workers must be 1..32 and divide the page count')
    original = read_swaps()
    others = [row for row in original if not row[0].startswith('xswap')]
    if others and not args.takeover_swap:
        parser.error('use --takeover-swap to temporarily replace other swap devices')
    for name, *_ in original:
        if name.startswith('xswap') and not (DEBUG / f'type{name[5:]}' / 'kv_port').exists():
            parser.error('active xswap device is not rswap')
    output = args.output.resolve() if args.output else pathlib.Path(tempfile.mkdtemp(prefix='rswap-swapin-'))
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
            cg = pathlib.Path(tempfile.mkdtemp(prefix='rswap-swapin-', dir='/sys/fs/cgroup'))
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
