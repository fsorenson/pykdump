#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Wait-Chain / Lock-Dependency Graph Builder for pykdump.

Scans all TASK_UNINTERRUPTIBLE (UN) tasks, classifies what each task is blocked
on (mutex/rwsem owner, jbd2 journal commit, workqueue flush, block I/O, folio
writeback, SunRPC, XFS iclog, etc.), builds a directed waiter -> blocker graph,
detects deadlock cycles, and prints root blockers with their dependent chains.
"""

from __future__ import print_function

import argparse
from collections import defaultdict
import re
import sys

from pykdump.API import *
from LinuxDump.Tasks import TaskTable, decode_waitq
from LinuxDump.fs import getMount

VERSION = "lock_graph.py 0.1"

SCHED_FUNCS = {
    "__schedule",
    "schedule",
    "schedule_timeout",
    "schedule_timeout_uninterruptible",
    "schedule_timeout_killable",
    "io_schedule",
    "io_schedule_timeout",
    "bit_wait",
    "bit_wait_io",
    "__wait_on_bit",
    "out_of_line_wait_on_bit",
    "__wait_for_common",
    "wait_for_completion",
    "wait_for_common",
    "preempt_schedule",
    "preempt_schedule_thunk",
}


def sym_only(func_str):
    return func_str.split("+")[0].split(".")[0].strip()


def parse_bt_frames(pid):
    """Run crash 'bt <pid>' and return list of (frame_idx, func_name, sp_addr)."""
    out = exec_crash_command("bt {}".format(pid))
    frames = []
    for line in out.splitlines():
        m = re.match(r"^\s*#(\d+)\s+\[([0-9a-fA-F]+)\]\s+(\S+)\s+at\s+", line)
        if m:
            frames.append((int(m.group(1)), sym_only(m.group(3)), int(m.group(2), 16)))
    return frames


def try_mutex_owner(lock_addr):
    """Return (owner_pid, owner_comm) if lock_addr looks like a held struct mutex."""
    try:
        m = readSU("struct mutex", lock_addr)
        owner_val = int(m.owner.counter)
        task_addr = owner_val & ~0x7
        if task_addr > 0xffff000000000000:
            t = readSU("struct task_struct", task_addr)
            return int(t.pid), str(t.comm)
    except Exception:
        pass
    return None


def try_rwsem_owner(lock_addr):
    """Return (owner_pid, owner_comm) if lock_addr looks like a held struct rw_semaphore."""
    try:
        rw = readSU("struct rw_semaphore", lock_addr)
        owner_val = int(rw.owner.counter)
        task_addr = owner_val & ~0x7
        if task_addr > 0xffff000000000000:
            t = readSU("struct task_struct", task_addr)
            return int(t.pid), str(t.comm)
    except Exception:
        pass
    return None


def build_jbd2_waiter_map():
    """Map waiter PID -> (kjournald2_pid, reason) for tasks blocked on jbd2 waitqs."""
    waiter_map = {}
    try:
        for _, superblk, fstype, _, mnt in getMount():
            if str(fstype) != "ext4":
                continue
            sb = readSU("struct super_block", superblk)
            if not sb.s_fs_info:
                continue
            sbi = readSU("struct ext4_sb_info", int(sb.s_fs_info))
            j = sbi.s_journal
            if not j or not j.j_task:
                continue
            jpid = int(j.j_task.pid)
            jdev = str(j.j_devname) if j.j_devname else str(mnt)
            for wname, wq in [
                ("j_wait_transaction_locked", j.j_wait_transaction_locked),
                ("j_wait_done_commit", j.j_wait_done_commit),
                ("j_wait_updates", j.j_wait_updates),
            ]:
                try:
                    for t in decode_waitq(wq):
                        waiter_map[int(t.pid)] = (jpid, "jbd2:{} ({})".format(wname, jdev))
                except Exception:
                    pass
    except Exception:
        pass
    return waiter_map


def build_wq_active_map():
    """Map workqueue_struct addr -> list of active worker PIDs."""
    wq_workers = defaultdict(list)
    if not symbol_exists("workqueues"):
        return wq_workers
    try:
        wq_head = sym2addr("workqueues")
        for wq in readSUListFromHead(wq_head, "list", "struct workqueue_struct"):
            pwqs = readSUListFromHead(int(wq.pwqs), "pwqs_node", "struct pool_workqueue", warn=False)
            seen_pools = set()
            for pwq in pwqs:
                if not pwq.pool:
                    continue
                paddr = int(pwq.pool)
                if paddr in seen_pools:
                    continue
                seen_pools.add(paddr)
                for w in readSUListFromHead(int(pwq.pool.workers), "node", "struct worker", warn=False):
                    try:
                        if w.current_pwq and w.current_pwq.wq and int(w.current_pwq.wq) == int(wq) and w.task:
                            wq_workers[int(wq)].append((int(w.task.pid), str(w.task.comm)))
                    except Exception:
                        pass
    except Exception:
        pass
    return wq_workers


def find_lock_holder_from_bt_f(pid, funcs):
    """Best-effort scan of 'bt -f <pid>' stack words near lock slowpath frames."""
    is_mutex = any("mutex_lock" in f for f in funcs)
    is_rwsem = any("rwsem_down_" in f or "down_read" in f or "down_write" in f for f in funcs)
    if not (is_mutex or is_rwsem):
        return None

    out = exec_crash_command("bt -f {}".format(pid))
    # Collect stack words in the first ~10 frames
    words = []
    in_early = False
    for line in out.splitlines():
        m = re.match(r"^\s*#(\d+)\s+\[", line)
        if m:
            fidx = int(m.group(1))
            in_early = fidx <= 8
            continue
        if in_early and ":" in line:
            parts = line.split(":", 1)[1].split()
            for p in parts:
                if re.match(r"^[0-9a-fA-F]{16}$", p):
                    val = int(p, 16)
                    if val > 0xffff000000000000:
                        words.append(val)

    for w in words:
        if is_mutex:
            res = try_mutex_owner(w)
            if res and res[0] != pid:
                return ("mutex 0x{:x}".format(w), res[0], res[1])
        if is_rwsem:
            res = try_rwsem_owner(w)
            if res and res[0] != pid:
                return ("rwsem 0x{:x}".format(w), res[0], res[1])
    return None


def classify_blocker(pid, comm, frames, jbd2_map, wq_workers):
    """
    Return (edges_list, root_category, detail_str).
    edges_list: list of (target_pid, reason) if blocked on another task.
    """
    funcs = [f for _, f, _ in frames]
    top_non_sched = next((f for f in funcs if f not in SCHED_FUNCS), funcs[0] if funcs else "?")

    if pid in jbd2_map:
        jpid, reason = jbd2_map[pid]
        if jpid != pid:
            return ([(jpid, reason)], None, reason)

    if "__flush_workqueue" in funcs:
        # Try to match XFS workqueue by comm (e.g. xfsaild/loop3 -> xfs-cil/loop3)
        if comm.startswith("xfsaild/") and symbol_exists("workqueues"):
            dev = comm.split("/", 1)[1]
            target_wq_name = "xfs-cil/{}".format(dev)
            wq_head = sym2addr("workqueues")
            for wq in readSUListFromHead(wq_head, "list", "struct workqueue_struct"):
                if str(wq.name) == target_wq_name:
                    workers = wq_workers.get(int(wq), [])
                    if workers:
                        edges = [(wpid, "flush_wq:{}".format(target_wq_name)) for wpid, _ in workers if wpid != pid]
                        if edges:
                            return (edges, None, "flush_wq:{}".format(target_wq_name))

    lock_res = find_lock_holder_from_bt_f(pid, funcs)
    if lock_res:
        lkind, hpid, _ = lock_res
        return ([(hpid, lkind)], None, lkind)

    # Root blocker classification
    if "__wait_on_buffer" in funcs:
        return ([], "BLOCK_IO (buffer_head)", top_non_sched)
    if "blk_io_schedule" in funcs or "__iomap_dio_rw" in funcs:
        return ([], "BLOCK_IO (direct/bio)", top_non_sched)
    if "folio_wait_writeback" in funcs:
        return ([], "FOLIO_WRITEBACK", top_non_sched)
    if "folio_wait_bit_common" in funcs or "folio_lock" in funcs:
        return ([], "FOLIO_LOCK", top_non_sched)
    if "rpc_wait_for_completion_task" in funcs or "rpc_wait_bit_killable" in funcs:
        return ([], "SUNRPC", top_non_sched)
    if "xlog_state_get_iclog_space" in funcs:
        return ([], "XFS_ICLOG_IO", top_non_sched)
    if any("smb2" in f or "cifs" in f for f in funcs):
        return ([], "SMB_CIFS", top_non_sched)
    if any("mutex_lock" in f or "rwsem" in f or "down_" in f for f in funcs):
        return ([], "LOCK_UNKNOWN_OWNER", top_non_sched)

    return ([], "OTHER ({})".format(top_non_sched), top_non_sched)


def find_cycles(edges):
    """Detect directed cycles in pid -> [(target_pid, reason)] graph."""
    visited = {}  # 0=visiting, 1=done
    cycles = []
    stack = []

    def dfs(u):
        visited[u] = 0
        stack.append(u)
        for v, _ in edges.get(u, []):
            if v not in visited:
                dfs(v)
            elif visited[v] == 0:
                idx = stack.index(v)
                cycles.append(stack[idx:] + [v])
        stack.pop()
        visited[u] = 1

    for node in list(edges.keys()):
        if node not in visited:
            dfs(node)
    return cycles


def main():
    parser = argparse.ArgumentParser(
        prog="lock_graph",
        description="Build wait-chain / lock-dependency graph across UN tasks.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all individual leaf waiters")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    args = parser.parse_args()

    if args.version:
        print(VERSION)
        return

    tt = TaskTable()
    pid_to_task = {t.pid: t for t in tt.allTasks()}

    un_tasks = []
    for t in tt.allTasks():
        try:
            st = int(t.state)
            # Match TASK_UNINTERRUPTIBLE (2), excluding TASK_IDLE (TASK_UNINTERRUPTIBLE | TASK_NOLOAD = 0x402)
            if (st & 2) and (st & 0x400) == 0:
                un_tasks.append(t)
        except Exception:
            pass

    if not un_tasks:
        print("No TASK_UNINTERRUPTIBLE (UN) tasks found.")
        return

    jbd2_map = build_jbd2_waiter_map()
    wq_workers = build_wq_active_map()

    edges = defaultdict(list)       # waiter_pid -> [(target_pid, reason)]
    rev_edges = defaultdict(list)   # target_pid -> [(waiter_pid, reason)]
    roots = defaultdict(list)       # category -> [(pid, comm, detail)]
    task_info = {}                  # pid -> (comm, frames)

    for t in un_tasks:
        pid = int(t.pid)
        comm = str(t.comm)
        frames = parse_bt_frames(pid)
        task_info[pid] = (comm, frames)
        t_edges, root_cat, detail = classify_blocker(pid, comm, frames, jbd2_map, wq_workers)
        if t_edges:
            for target_pid, reason in t_edges:
                edges[pid].append((target_pid, reason))
                rev_edges[target_pid].append((pid, reason))
        elif root_cat:
            roots[root_cat].append((pid, comm, detail))

    print("=== Wait-Chain Summary ({} UN tasks) ===".format(len(un_tasks)))
    for cat, items in sorted(roots.items(), key=lambda kv: len(kv[1]), reverse=True):
        print("  {:<26} : {} root task(s)".format(cat, len(items)))

    cycles = find_cycles(edges)
    if cycles:
        print("\n=== DEADLOCK CYCLES DETECTED ({}) ===".format(len(cycles)))
        for cyc in cycles:
            chain = " -> ".join("{}({})".format(p, task_info.get(p, (pid_to_task[p].comm if p in pid_to_task else "?", []))[0]) for p in cyc)
            print("  CYCLE: {}".format(chain))

    print("\n=== Dependency Chains (Root Blockers -> Dependent Waiters) ===")

    def print_dependents(target_pid, indent, seen):
        deps = rev_edges.get(target_pid, [])
        if not deps:
            return
        for wpid, reason in sorted(deps, key=lambda x: x[0]):
            wcomm = task_info.get(wpid, (pid_to_task[wpid].comm if wpid in pid_to_task else "?", []))[0]
            print("{}<- PID {:<7} {:<16} [{}]".format(indent, wpid, wcomm, reason))
            if wpid not in seen:
                seen.add(wpid)
                print_dependents(wpid, indent + "   ", seen)

    # First print root blockers that have dependent waiters
    printed_cats = set()
    for cat, items in sorted(roots.items(), key=lambda kv: len(kv[1]), reverse=True):
        with_deps = [it for it in items if it[0] in rev_edges]
        without_deps = [it for it in items if it[0] not in rev_edges]

        if with_deps:
            print("\n[{}] (with dependent waiters):".format(cat))
            for pid, comm, detail in sorted(with_deps):
                print("  ROOT PID {:<7} {:<16} ({})".format(pid, comm, detail))
                print_dependents(pid, "    ", {pid})

        if without_deps:
            print("\n[{}] ({} standalone task(s)):".format(cat, len(without_deps)))
            show = without_deps if args.verbose else without_deps[:8]
            for pid, comm, detail in sorted(show):
                print("  PID {:<7} {:<16} ({})".format(pid, comm, detail))
            if not args.verbose and len(without_deps) > 8:
                print("  ... ({} more; use -v to list all)".format(len(without_deps) - 8))


if __name__ == "__main__":
    main()
