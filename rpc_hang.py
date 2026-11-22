#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
End-to-end NFS / SunRPC hang & bottleneck correlator for pykdump.

Correlates:
  - Blocked / owning user processes (tk_owner -> task_struct)
  - In-flight RPC tasks (rpc_task: proc, age, state, waitqueue, action, xid, retries)
  - RPC transports (rpc_xprt / sock_xprt: slots, queue lengths, server, mountpoints)
  - Underlying TCP/UDP socket state (sk_state, unacked bytes, zero-window, retransmits, buffers)
"""

from __future__ import print_function

import argparse
from collections import defaultdict
import sys

from pykdump.API import *
from LinuxDump.Tasks import TaskTable
from LinuxDump.Time import tkr_time, sched_clock_j
from LinuxDump.inet import ntodots, ntodots6
from LinuxDump.inet.proto import tcpState, IP_sock, P_FAMILIES
from LinuxDump.nfsrpc import get_nfs_mounts

VERSION = "rpc_hang.py 0.1"

# XPRT state bits from include/linux/sunrpc/xprt.h
XPRT_LOCKED = 0
XPRT_CONNECTED = 1
XPRT_CONNECTING = 2
XPRT_CLOSE_WAIT = 3
XPRT_BOUND = 4
XPRT_BINDING = 5
XPRT_CLOSING = 6
XPRT_OFFLINE = 7
XPRT_REMOVE = 8
XPRT_CONGESTED = 9
XPRT_CWND_WAIT = 10
XPRT_WRITE_SPACE = 11
XPRT_SND_IS_WAIT = 12

XPRT_STATE_NAMES = {
    XPRT_LOCKED: "LOCKED",
    XPRT_CONNECTED: "CONNECTED",
    XPRT_CONNECTING: "CONNECTING",
    XPRT_CLOSE_WAIT: "CLOSE_WAIT",
    XPRT_BOUND: "BOUND",
    XPRT_BINDING: "BINDING",
    XPRT_CLOSING: "CLOSING",
    XPRT_OFFLINE: "OFFLINE",
    XPRT_REMOVE: "REMOVE",
    XPRT_CONGESTED: "CONGESTED",
    XPRT_CWND_WAIT: "CWND_WAIT",
    XPRT_WRITE_SPACE: "WRITE_SPACE",
    XPRT_SND_IS_WAIT: "SND_IS_WAIT",
}

# RPC_TASK_RUNSTATE bits from include/linux/sunrpc/sched.h
RPC_TASK_RUNNING = 0
RPC_TASK_QUEUED = 1
RPC_TASK_ACTIVE = 2
RPC_TASK_NEED_XMIT = 3
RPC_TASK_NEED_RECV = 4
RPC_TASK_MSG_PIN_WAIT = 5
RPC_TASK_MSG_RECV = 6
RPC_TASK_MSG_RECV_WAIT = 7

RUNSTATE_NAMES = {
    RPC_TASK_RUNNING: "RUNNING",
    RPC_TASK_QUEUED: "QUEUED",
    RPC_TASK_ACTIVE: "ACTIVE",
    RPC_TASK_NEED_XMIT: "NEED_XMIT",
    RPC_TASK_NEED_RECV: "NEED_RECV",
    RPC_TASK_MSG_PIN_WAIT: "PIN_WAIT",
    RPC_TASK_MSG_RECV: "RECV",
    RPC_TASK_MSG_RECV_WAIT: "RECV_WAIT",
}


def decode_bits(val, names):
    out = [name for bit, name in sorted(names.items()) if val & (1 << bit)]
    return "|".join(out) if out else "0x{:x}".format(val)


def sym_name(addr):
    if not addr:
        return "-"
    s = addr2sym(addr)
    return s if s else "0x{:x}".format(int(addr))


def net_generic(net, net_id):
    ng = net.gen
    ptr = ng.ptr
    try:
        ng_len = ng.len
        newstyle = False
    except KeyError:
        ng_len = ng.s.len
        newstyle = True
    if net_id == 0 or net_id > ng_len:
        return 0
    return int(ptr[net_id] if newstyle else ptr[net_id - 1])


def get_all_rpc_clients():
    all_clients_addr = sym2addr("all_clients")
    if not all_clients_addr:
        if not symbol_exists("sunrpc_net_id"):
            return []
        net_id = readSymbol("sunrpc_net_id")
        net = readSymbol("init_net")
        sn_addr = net_generic(net, net_id)
        if not sn_addr:
            return []
        sn = readSU("struct sunrpc_net", sn_addr)
        all_clients_addr = int(sn.all_clients)
    return readSUListFromHead(all_clients_addr, "cl_clients", "struct rpc_clnt")


def build_xprt_mount_map():
    """Map rpc_xprt addr -> set of (mountpoint, fstype, servername)."""
    xprt_mounts = defaultdict(set)
    try:
        for srv_host, srv, mnt in get_nfs_mounts():
            try:
                clnt = srv.Rpccl
                if clnt and clnt.cl_xprt:
                    xprt_mounts[int(clnt.cl_xprt)].add((str(mnt), str(srv_host)))
            except Exception:
                pass
    except Exception:
        pass
    return xprt_mounts


def extract_socket_info(xprt):
    """Extract socket and TCP state from sock_xprt."""
    info = {
        "local": "-",
        "remote": "-",
        "sk_state": "-",
        "sk_err": 0,
        "rmem": 0,
        "rcvbuf": 0,
        "wmem": 0,
        "sndbuf": 0,
        "tcp": None,
    }
    try:
        sx = readSU("struct sock_xprt", int(xprt))
        if not sx.inet:
            return info
        sk = sx.inet
        try:
            info["sk_err"] = int(sk.sk_err)
        except Exception:
            pass

        try:
            info["rcvbuf"] = int(sk.sk_rcvbuf)
            info["wmem"] = int(sk.sk_wmem_queued)
            info["sndbuf"] = int(sk.sk_sndbuf)
            try:
                info["rmem"] = int(sk.sk_rmem_alloc.counter)
            except Exception:
                info["rmem"] = int(sk.sk_backlog.rmem_alloc.counter)
        except Exception:
            pass

        try:
            ips = IP_sock(sk)
            if ips.family == P_FAMILIES.PF_INET6:
                src_s = "[{}]".format(ntodots6(ips.src))
                dst_s = "[{}]".format(ntodots6(ips.dst))
            else:
                src_s = ntodots(ips.src)
                dst_s = ntodots(ips.dst)
            info["local"] = "{}:{}".format(src_s, ips.sport)
            info["remote"] = "{}:{}".format(dst_s, ips.dport)
            try:
                info["sk_state"] = str(tcpState[ips.state])
            except Exception:
                info["sk_state"] = str(ips.state)
        except Exception:
            pass

        if int(xprt.prot) == 6:  # IPPROTO_TCP
            try:
                tp = readSU("struct tcp_sock", int(sk))
                snd_una = int(tp.snd_una) & 0xffffffff
                snd_nxt = int(tp.snd_nxt) & 0xffffffff
                unacked = (snd_nxt - snd_una) & 0xffffffff
                info["tcp"] = {
                    "snd_wnd": int(tp.snd_wnd),
                    "rcv_wnd": int(tp.rcv_wnd),
                    "packets_out": int(tp.packets_out),
                    "retrans_out": int(tp.retrans_out),
                    "total_retrans": int(tp.total_retrans),
                    "unacked_bytes": unacked,
                }
            except Exception:
                pass
    except Exception:
        pass
    return info


def get_xprt_addr_str(xprt):
    try:
        s = str(xprt.address_strings[0])
        if s:
            return s
    except Exception:
        pass
    try:
        if xprt.servername:
            return str(xprt.servername)
    except Exception:
        pass
    return "0x{:x}".format(int(xprt))


def task_age_sec(tk, now_ns):
    try:
        start = int(tk.tk_start)
        if start and now_ns > start:
            return (now_ns - start) / 1e9
    except Exception:
        pass
    return None


def classify_xprt_bottleneck(xprt, sock_info, tasks):
    """Return a short diagnosis string for an xprt."""
    notes = []
    state = int(xprt.state)
    if not (state & (1 << XPRT_CONNECTED)):
        notes.append("DISCONNECTED")
    if state & (1 << XPRT_CWND_WAIT):
        notes.append("CWND_WAIT(cong={}/{})".format(int(xprt.cong), int(xprt.cwnd)))
    if int(xprt.backlog.qlen) > 0:
        notes.append("SLOT_EXHAUSTION(backlog={})".format(int(xprt.backlog.qlen)))
    if int(xprt.sending.qlen) > 0:
        notes.append("SENDING_Q({})".format(int(xprt.sending.qlen)))
    if sock_info["sk_err"]:
        notes.append("SK_ERR={}".format(sock_info["sk_err"]))
    tcp = sock_info["tcp"]
    if tcp:
        if tcp["snd_wnd"] == 0 and tcp["unacked_bytes"] > 0:
            notes.append("ZERO_WINDOW")
        if tcp["retrans_out"] > 0:
            notes.append("RETRANS_OUT={}".format(tcp["retrans_out"]))
        if tcp["unacked_bytes"] > 0:
            notes.append("UNACKED={}B".format(tcp["unacked_bytes"]))
    if int(xprt.pending.qlen) > 0 and not notes:
        notes.append("WAITING_ON_SERVER({} pending)".format(int(xprt.pending.qlen)))
    return ", ".join(notes) if notes else "IDLE/OK"


def collect_data():
    now_ns = 0
    try:
        t = tkr_time()
        if t is None:
            t = sched_clock_j()
        now_ns = int(t) if t else 0
    except Exception:
        pass

    tt = TaskTable()
    pid_to_task = {t.pid: t for t in tt.allTasks()}

    clients = get_all_rpc_clients()
    xprts_by_addr = {}
    tasks_by_xprt = defaultdict(list)
    all_tasks = []

    for cl in clients:
        if cl.cl_xprt:
            xaddr = int(cl.cl_xprt)
            if xaddr not in xprts_by_addr:
                xprts_by_addr[xaddr] = cl.cl_xprt

        for tk in readSUListFromHead(int(cl.cl_tasks), "tk_task", "struct rpc_task", warn=False):
            xprt = tk.tk_xprt if tk.tk_xprt else cl.cl_xprt
            xaddr = int(xprt) if xprt else 0
            if xprt and xaddr not in xprts_by_addr:
                xprts_by_addr[xaddr] = xprt
            tasks_by_xprt[xaddr].append((cl, tk))
            all_tasks.append((cl, tk, xaddr))

    return now_ns, pid_to_task, xprts_by_addr, tasks_by_xprt, all_tasks


def format_proc_name(cl, tk):
    try:
        if tk.tk_msg and tk.tk_msg.rpc_proc and tk.tk_msg.rpc_proc.p_name:
            return str(tk.tk_msg.rpc_proc.p_name)
    except Exception:
        pass
    try:
        proc_idx = int(tk.tk_msg.rpc_proc)
        return "proc#{}".format(proc_idx)
    except Exception:
        return "?"


def print_report(args):
    now_ns, pid_to_task, xprts_by_addr, tasks_by_xprt, all_tasks = collect_data()
    xprt_mounts = build_xprt_mount_map()

    if not xprts_by_addr and not all_tasks:
        print("No active SunRPC clients/transports found.")
        return

    print("=== RPC Transports & Socket Correlation ({} transports, {} active RPC tasks) ===".format(
        len(xprts_by_addr), len(all_tasks)
    ))

    for xaddr, xprt in sorted(xprts_by_addr.items(), key=lambda kv: get_xprt_addr_str(kv[1])):
        tlist = tasks_by_xprt.get(xaddr, [])
        if args.active_only and not tlist and int(xprt.queuelen) == 0:
            continue

        sock_info = extract_socket_info(xprt)
        diag = classify_xprt_bottleneck(xprt, sock_info, tlist)
        srv_str = get_xprt_addr_str(xprt)
        if args.server and args.server not in srv_str:
            continue

        print("\n[xprt 0x{:x}] server={}  diag=[{}]".format(xaddr, srv_str, diag))
        print("  state={}  slots={}/{} (max_ever={})  qlen(bind/send/pend/bklog)={}/{}/{}/{}".format(
            decode_bits(int(xprt.state), XPRT_STATE_NAMES),
            int(xprt.num_reqs),
            int(xprt.max_reqs),
            int(xprt.stat.max_slots),
            int(xprt.binding.qlen),
            int(xprt.sending.qlen),
            int(xprt.pending.qlen),
            int(xprt.backlog.qlen),
        ))

        if sock_info["tcp"] is not None:
            tp = sock_info["tcp"]
            print("  tcp {} -> {} [{}]  unacked={}B  snd_wnd={}  retrans={}/{}  wmem={}/{}  rmem={}/{}".format(
                sock_info["local"],
                sock_info["remote"],
                sock_info["sk_state"],
                tp["unacked_bytes"],
                tp["snd_wnd"],
                tp["retrans_out"],
                tp["total_retrans"],
                sock_info["wmem"],
                sock_info["sndbuf"],
                sock_info["rmem"],
                sock_info["rcvbuf"],
            ))
        elif sock_info["sk_state"] != "-":
            print("  sock {} -> {} [{}]  sk_err={}".format(
                sock_info["local"], sock_info["remote"], sock_info["sk_state"], sock_info["sk_err"]
            ))

        mounts = sorted(xprt_mounts.get(xaddr, []))
        if mounts:
            mnt_str = ", ".join(m for m, _ in mounts)
            print("  mounts: {}".format(mnt_str))

        if not tlist:
            continue

        print("  {:<7} {:<16} {:<6} {:<8} {:<16} {:<16} {:<20} {}".format(
            "PID", "COMM(STATE)", "TK_PID", "AGE(s)", "PROC", "WAITQ", "ACTION", "XID/TRANS"
        ))

        rows = []
        for cl, tk in tlist:
            age = task_age_sec(tk, now_ns)
            if args.min_age and (age is None or age < args.min_age):
                continue
            rows.append((age if age is not None else -1.0, cl, tk))

        rows.sort(key=lambda r: r[0], reverse=True)
        for age, cl, tk in rows:
            owner_pid = int(tk.tk_owner)
            tinfo = pid_to_task.get(owner_pid)
            if tinfo:
                try:
                    st = str(tinfo.ts.state)
                except Exception:
                    st_val = int(tinfo.state)
                    st = "RU" if st_val == 0 else ("UN" if (st_val & 2) else ("IN" if (st_val & 1) else hex(st_val)))
                comm_st = "{}({})".format(tinfo.comm[:12], st)
            else:
                comm_st = "-"
            age_s = "{:.2f}".format(age) if age >= 0 else "-"
            proc_s = format_proc_name(cl, tk)
            try:
                wq_s = str(tk.tk_waitqueue.name) if tk.tk_waitqueue else "-"
            except Exception:
                wq_s = "-"
            act_s = sym_name(tk.tk_action)

            xid_s = "-"
            try:
                if tk.tk_rqstp:
                    rq = tk.tk_rqstp
                    xid_s = "0x{:08x} ntrans={}".format(int(rq.rq_xid), int(rq.rq_ntrans))
            except Exception:
                pass

            print("  {:<7} {:<16} {:<6} {:<8} {:<16} {:<16} {:<20} {}".format(
                owner_pid,
                comm_st[:16],
                int(tk.tk_pid),
                age_s,
                proc_s[:16],
                wq_s[:16],
                act_s[:20],
                xid_s,
            ))


def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="rpc_hang",
        description="Correlate blocked processes, SunRPC tasks, transports, and TCP sockets.",
    )
    p.add_argument("-a", "--active-only", action="store_true", help="Only show transports with active tasks/queues")
    p.add_argument("-s", "--server", help="Filter by server address/hostname substring")
    p.add_argument("-m", "--min-age", type=float, default=0.0, help="Only show RPC tasks older than N seconds")
    p.add_argument("--version", action="store_true", help="Show version and exit")
    return p


def main():
    parser = build_arg_parser()
    args = parser.parse_args()
    if args.version:
        print(VERSION)
        return
    print_report(args)


if __name__ == "__main__":
    main()
