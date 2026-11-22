#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ext4 / jbd2 journal and transaction state inspector for pykdump.

Displays:
  - Mounted ext4 filesystems and their jbd2 journal_t state
  - Sequence numbers, journal ring space, j_flags, j_errno, j_barrier_count
  - Running, committing, and checkpoint transactions (state, age, handles, credits)
  - Tasks blocked on jbd2 wait queues (j_wait_transaction_locked, j_wait_done_commit, etc.)
  - Optional (-v): locked/in-flight buffer_heads in committing/checkpoint transactions
"""

from __future__ import print_function

import argparse
import sys

from pykdump.API import *
from LinuxDump.fs import getMount
from LinuxDump.Tasks import decode_waitq
from LinuxDump.Time import tkr_time, j_delay

VERSION = "jbd2_show.py 0.1"

# JBD2 journal flags from include/linux/jbd2.h
JBD2_FLAG_NAMES = {
    0: "UNMOUNT",
    1: "ABORT",
    2: "ACK_ERR",
    3: "FLUSHED",
    4: "LOADED",
    5: "BARRIER",
    6: "ABORT_ON_SYNCDATA_ERR",
    7: "REC_ERR",
    8: "FAST_COMMIT_ONGOING",
    9: "FULL_COMMIT_ONGOING",
    10: "FAST_COMMIT_NEED_COMMIT",
    11: "COMMIT_CALLBACK_DONE",
}

T_STATE_NAMES = {
    0: "T_RUNNING",
    1: "T_LOCKED",
    2: "T_SWITCH",
    3: "T_FLUSH",
    4: "T_COMMIT",
    5: "T_COMMIT_DFLUSH",
    6: "T_COMMIT_JFLUSH",
    7: "T_COMMIT_CALLBACK",
    8: "T_FINISHED",
}

# buffer_head b_state bits (include/linux/buffer_head.h)
BH_UPTODATE = 0
BH_DIRTY = 1
BH_LOCK = 2
BH_REQ = 3
BH_MAPPED = 4
BH_NEW = 5
BH_ASYNC_READ = 6
BH_ASYNC_WRITE = 7
BH_DELAY = 8
BH_BOUNDARY = 9
BH_WRITE_EIO = 10
BH_UNWRITTEN = 11
BH_QUIET = 12
BH_META = 13
BH_PRIO = 14
BH_JBD = 18

BH_STATE_NAMES = {
    BH_UPTODATE: "Uptodate",
    BH_DIRTY: "Dirty",
    BH_LOCK: "Lock",
    BH_REQ: "Req",
    BH_MAPPED: "Mapped",
    BH_ASYNC_READ: "AsyncRead",
    BH_ASYNC_WRITE: "AsyncWrite",
    BH_DELAY: "Delay",
    BH_WRITE_EIO: "WriteEIO",
    BH_META: "Meta",
    BH_JBD: "JBD",
}


def decode_bits(val, names):
    out = [name for bit, name in sorted(names.items()) if val & (1 << bit)]
    return "|".join(out) if out else "0"


def get_ext4_journals():
    """Return list of (mnt, devname, sb, ext4_sb_info, journal_t) for ext4 mounts."""
    results = []
    seen_journals = set()
    for vfsmount, superblk, fstype, devname, mnt in getMount():
        if str(fstype) != "ext4":
            continue
        sb = readSU("struct super_block", superblk)
        if not sb.s_fs_info:
            continue
        sbi = readSU("struct ext4_sb_info", int(sb.s_fs_info))
        j = sbi.s_journal if sbi.s_journal else None
        jaddr = int(j) if j else 0
        if jaddr and jaddr in seen_journals:
            continue
        if jaddr:
            seen_journals.add(jaddr)
        results.append((str(mnt), str(devname), sb, sbi, j))
    return results


def count_jh_ring(head_ptr, next_field="b_tnext", limit=10000):
    """Count journal_heads in a circular doubly-linked jh list and collect locked bhs."""
    if not head_ptr:
        return 0, []
    start = int(head_ptr)
    cur = start
    count = 0
    locked_bhs = []
    while cur and count < limit:
        jh = readSU("struct journal_head", cur)
        count += 1
        try:
            if jh.b_bh:
                bh = jh.b_bh
                b_state = int(bh.b_state)
                if b_state & (1 << BH_LOCK):
                    locked_bhs.append((int(bh), int(bh.b_blocknr), b_state))
        except Exception:
            pass
        nxt = int(getattr(jh, next_field))
        if not nxt or nxt == start:
            break
        cur = nxt
    return count, locked_bhs


def print_transaction(label, tx, now_ns, jiffies_val, verbose=0):
    if not tx:
        print("  {}: none".format(label))
        return
    # t_state is an anonymous enum in struct transaction_s, which pykdump cannot resolve by name
    t_state_off = member_offset("struct transaction_s", "t_state")
    t_state = readU32(int(tx) + t_state_off) if t_state_off >= 0 else -1
    state_str = T_STATE_NAMES.get(t_state, str(t_state))

    age_str = "-"
    try:
        st_ns = int(tx.t_start_time)
        if st_ns and now_ns and now_ns > st_ns:
            age_str = "{:.2f}s".format((now_ns - st_ns) / 1e9)
        else:
            age_str = str(j_delay(int(tx.t_start), jiffies_val)).strip()
    except Exception:
        pass

    print(
        "  {} [0x{:x}]: tid={}  state={}  age={}  updates={}  handles={}  credits={}  nr_bufs={}".format(
            label,
            int(tx),
            int(tx.t_tid),
            state_str,
            age_str,
            int(tx.t_updates.counter),
            int(tx.t_handle_count.counter),
            int(tx.t_outstanding_credits.counter),
            int(tx.t_nr_buffers),
        )
    )

    if verbose >= 1:
        for lname, ptr, fld in [
            ("t_buffers", tx.t_buffers, "b_tnext"),
            ("t_shadow_list", tx.t_shadow_list, "b_tnext"),
            ("t_forget", tx.t_forget, "b_tnext"),
            ("t_checkpoint_list", tx.t_checkpoint_list, "b_cpnext"),
        ]:
            if ptr:
                cnt, locked = count_jh_ring(ptr, next_field=fld)
                print("    {}: {} journal_heads ({} locked bhs)".format(lname, cnt, len(locked)))
                for bh_addr, blk, bstate in locked[:10]:
                    print(
                        "      locked <buffer_head 0x{:x}> blocknr={} state={}".format(
                            bh_addr, blk, decode_bits(bstate, BH_STATE_NAMES)
                        )
                    )


def get_waitq_tasks(wq):
    """Return list of task_struct wait entries from wait_queue_head_t."""
    tasks = []
    try:
        for wq_entry in decode_waitq(wq):
            tasks.append(wq_entry)
    except Exception:
        pass
    return tasks


def print_waiters(j):
    waitqs = [
        ("j_wait_transaction_locked", j.j_wait_transaction_locked),
        ("j_wait_done_commit", j.j_wait_done_commit),
        ("j_wait_commit", j.j_wait_commit),
        ("j_wait_updates", j.j_wait_updates),
        ("j_wait_reserved", j.j_wait_reserved),
        ("j_fc_wait", j.j_fc_wait),
    ]
    any_waiters = False
    for wname, wq in waitqs:
        try:
            head_addr = int(wq.head)
            next_addr = int(wq.head.next)
            if next_addr == head_addr or next_addr == 0:
                continue
        except Exception:
            continue

        waiters = get_waitq_tasks(wq)
        if not waiters:
            print("  waitq {}: non-empty".format(wname))
            any_waiters = True
            continue
        any_waiters = True
        print("  waitq {} ({} waiter(s)):".format(wname, len(waiters)))
        for t in waiters:
            try:
                print("    PID {:<7}  {:<16}  <task_struct 0x{:x}>".format(int(t.pid), str(t.comm), int(t)))
            except Exception:
                print("    {}".format(t))
    if not any_waiters:
        print("  waitqs: no blocked tasks")


def main():
    parser = argparse.ArgumentParser(
        prog="jbd2_show",
        description="Inspect ext4/jbd2 journal state, transactions, and blocked waiters.",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Show buffer_head lists and locked buffers")
    parser.add_argument("-m", "--mount", help="Filter by mountpoint or device substring")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    args = parser.parse_args()

    if args.version:
        print(VERSION)
        return

    now_ns = 0
    try:
        t = tkr_time()
        now_ns = int(t) if t else 0
    except Exception:
        pass
    jiffies_val = int(readSymbol("jiffies"))

    journals = get_ext4_journals()
    if not journals:
        print("No ext4 mounts found.")
        return

    for mnt, devname, sb, sbi, j in journals:
        if args.mount and args.mount not in mnt and args.mount not in devname:
            continue

        print("=== ext4 mount={} dev={} <super_block 0x{:x}> ===".format(mnt, devname, int(sb)))
        try:
            if int(sbi.s_last_error_code):
                print(
                    "  LAST_ERROR: code={} func={} line={} ino={} block={}".format(
                        int(sbi.s_last_error_code),
                        str(sbi.s_last_error_func),
                        int(sbi.s_last_error_line),
                        int(sbi.s_last_error_ino),
                        int(sbi.s_last_error_block),
                    )
                )
        except Exception:
            pass

        if not j:
            print("  s_journal: none (noaccel/nojournal)")
            continue

        jdev = str(j.j_devname) if j.j_devname else "-"
        jtask_str = "-"
        if j.j_task:
            jtask_str = "PID {} ({})".format(int(j.j_task.pid), str(j.j_task.comm))

        print("  <journal_t 0x{:x}> j_devname={}  kjournald2={}  j_flags={}  j_errno={}  barrier={}".format(
            int(j),
            jdev,
            jtask_str,
            decode_bits(int(j.j_flags), JBD2_FLAG_NAMES),
            int(j.j_errno),
            int(j.j_barrier_count),
        ))
        print("  seq: tail={}  commit={}  commit_req={}  next_tx={}  |  space: free={}/{} blocks (head={} tail={})".format(
            int(j.j_tail_sequence),
            int(j.j_commit_sequence),
            int(j.j_commit_request),
            int(j.j_transaction_sequence),
            int(j.j_free),
            int(j.j_total_len),
            int(j.j_head),
            int(j.j_tail),
        ))

        print_transaction("running_tx", j.j_running_transaction, now_ns, jiffies_val, args.verbose)
        print_transaction("committing_tx", j.j_committing_transaction, now_ns, jiffies_val, args.verbose)

        cp_head = j.j_checkpoint_transactions
        if cp_head:
            cp_list = []
            start = int(cp_head)
            cur = start
            while cur and len(cp_list) < 256:
                tx = readSU("struct transaction_s", cur)
                cp_list.append(tx)
                nxt = int(tx.t_cpnext)
                if not nxt or nxt == start:
                    break
                cur = nxt
            print("  checkpoint_txs: {} transaction(s)".format(len(cp_list)))
            if args.verbose >= 1:
                for idx, ctx in enumerate(cp_list):
                    print_transaction("  cp[{}]".format(idx), ctx, now_ns, jiffies_val, args.verbose)
        else:
            print("  checkpoint_txs: 0")

        print_waiters(j)
        print()


if __name__ == "__main__":
    main()
