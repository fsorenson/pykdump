#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Workqueue & Kworker Bottleneck Inspector for pykdump.

Walks the kernel's `workqueues` list, inspects each pool_workqueue and
worker_pool, correlates active kworkers (PID, state, current_func, age) with
queued/inactive work_structs, and highlights saturated or stalled workqueues.
"""

from __future__ import print_function

import argparse
from collections import Counter, defaultdict
import sys

from pykdump.API import *
from LinuxDump.Tasks import TaskTable
from LinuxDump.Time import tkr_time

VERSION = "wq_stuck.py 0.1"

# Workqueue flags from include/linux/workqueue.h
WQ_FLAG_NAMES = {
    1: "UNBOUND",
    2: "FREEZABLE",
    3: "MEM_RECLAIM",
    4: "HIGHPRI",
    5: "CPU_INTENSIVE",
    6: "SYSFS",
    7: "POWER_EFFICIENT",
    16: "DRAINING",
    17: "DESTROYING",
}


def decode_wq_flags(val):
    out = [name for bit, name in sorted(WQ_FLAG_NAMES.items()) if val & (1 << bit)]
    return "|".join(out) if out else "0"


def sym_name(addr):
    if not addr:
        return "-"
    s = addr2sym(int(addr))
    return s if s else "0x{:x}".format(int(addr))


def count_list_funcs(head_su, member, stype, func_attr="func", limit=2000):
    counts = Counter()
    total = 0
    try:
        for item in readSUListFromHead(int(head_su), member, stype, maxel=limit, warn=False):
            total += 1
            counts[sym_name(getattr(item, func_attr))] += 1
    except Exception:
        pass
    return total, counts


def worker_age_sec(worker, now_ns, jiffies_val, hz):
    try:
        cat = int(worker.current_at)
        if cat and now_ns and now_ns > cat:
            return (now_ns - cat) / 1e9
    except Exception:
        pass
    try:
        cs = int(worker.current_start)
        if cs:
            return ((jiffies_val - cs) & 0xffffffff) / float(hz)
    except Exception:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(
        prog="wq_stuck",
        description="Inspect Linux workqueues, active kworkers, and queued work_structs.",
    )
    parser.add_argument("-a", "--all", action="store_true", help="Show idle workqueues too")
    parser.add_argument("-w", "--wq", help="Filter by workqueue name substring")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    args = parser.parse_args()

    if args.version:
        print(VERSION)
        return

    if not symbol_exists("workqueues"):
        print("Symbol 'workqueues' not found in this kernel.")
        return

    now_ns = 0
    try:
        t = tkr_time()
        now_ns = int(t) if t else 0
    except Exception:
        pass
    jiffies_val = int(readSymbol("jiffies"))
    hz = int(sys_info.HZ) if hasattr(sys_info, "HZ") else 1000

    tt = TaskTable()
    pid_to_task = {t.pid: t for t in tt.allTasks()}

    wq_head = sym2addr("workqueues")
    wqs = readSUListFromHead(wq_head, "list", "struct workqueue_struct")

    pool_cache = {}
    shown = 0

    for wq in wqs:
        wq_name = str(wq.name)
        if args.wq and args.wq not in wq_name:
            continue

        max_active = int(wq.max_active)
        wq_flags = int(wq.flags)
        pwqs = readSUListFromHead(int(wq.pwqs), "pwqs_node", "struct pool_workqueue", warn=False)

        total_active = 0
        total_inactive = 0
        total_pool_queued = 0
        active_workers = []
        inactive_funcs = Counter()
        pool_queued_funcs = Counter()
        stalled_pools = 0

        for pwq in pwqs:
            nr_active = int(pwq.nr_active)
            total_active += nr_active
            inact_cnt, inact_c = count_list_funcs(pwq.inactive_works, "entry", "struct work_struct")
            total_inactive += inact_cnt
            inactive_funcs.update(inact_c)

            if not pwq.pool:
                continue
            paddr = int(pwq.pool)
            if paddr not in pool_cache:
                pool = pwq.pool
                pq_cnt, pq_c = count_list_funcs(pool.worklist, "entry", "struct work_struct")
                workers = readSUListFromHead(int(pool.workers), "node", "struct worker", warn=False)
                pool_cache[paddr] = (pool, pq_cnt, pq_c, workers)
            else:
                pool, pq_cnt, pq_c, workers = pool_cache[paddr]

            if bool(pool.cpu_stall):
                stalled_pools += 1

            # Collect workers currently executing work for this pwq (or on this pool if worklist queued)
            for w in workers:
                try:
                    if w.current_pwq and int(w.current_pwq) == int(pwq) and w.current_work:
                        active_workers.append((pool, w))
                except Exception:
                    pass

            if pq_cnt > 0 and nr_active > 0:
                total_pool_queued += pq_cnt
                pool_queued_funcs.update(pq_c)

        is_busy = (
            total_active > 0
            or total_inactive > 0
            or total_pool_queued > 0
            or stalled_pools > 0
            or int(wq.nr_drainers) > 0
        )
        if not args.all and not is_busy:
            continue

        shown += 1
        diag = []
        if total_inactive > 0:
            diag.append("SATURATED(inactive={})".format(total_inactive))
        if total_pool_queued > 0:
            diag.append("POOL_QUEUED({})".format(total_pool_queued))
        if stalled_pools > 0:
            diag.append("CPU_STALL({})".format(stalled_pools))
        diag_str = "  [" + ", ".join(diag) + "]" if diag else ""

        print("[wq 0x{:x}] {:<24} max_active={:<4} active={:<3} inactive={:<3} flags={}{}".format(
            int(wq), wq_name, max_active, total_active, total_inactive, decode_wq_flags(wq_flags), diag_str
        ))

        for pool, w in active_workers:
            pid = int(w.task.pid) if w.task else 0
            comm = str(w.task.comm) if w.task else "-"
            tinfo = pid_to_task.get(pid)
            if tinfo:
                try:
                    st_val = int(tinfo.state)
                    if st_val == 0:
                        st = "RU"
                    elif (st_val & 0x402) == 0x402:
                        st = "ID"
                    elif st_val & 2:
                        st = "UN"
                    elif st_val & 1:
                        st = "IN"
                    elif st_val & 4:
                        st = "ST"
                    else:
                        st = hex(st_val)
                except Exception:
                    st = "?"
            else:
                st = "?"
            age = worker_age_sec(w, now_ns, jiffies_val, hz)
            age_s = "{:.2f}s".format(age) if age is not None else "-"
            cfunc = sym_name(w.current_func)
            desc = str(w.desc) if w.desc else ""
            print("  worker PID {:<7} {:<16} ({}) cpu={:<3} age={:<9} func={} {}".format(
                pid, comm, st, int(pool.cpu), age_s, cfunc, ("[" + desc + "]") if desc else ""
            ))

        if inactive_funcs:
            top = ", ".join("{}x{}".format(fn, cnt) for fn, cnt in inactive_funcs.most_common(5))
            print("  inactive_works: {}".format(top))
        if pool_queued_funcs:
            top = ", ".join("{}x{}".format(fn, cnt) for fn, cnt in pool_queued_funcs.most_common(5))
            print("  pool_worklist:  {}".format(top))

    if shown == 0:
        print("No active/queued workqueues found (use -a to show all).")


if __name__ == "__main__":
    main()
