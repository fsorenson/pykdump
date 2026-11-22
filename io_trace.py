#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
End-to-End In-Flight I/O Tracer for pykdump.

Walks all in-flight block requests (via LinuxDump.block.get_all_requests) and
correlates each request -> bio chain -> page/folio -> address_space -> inode ->
filesystem & file path (plus iomap_dio / buffer_head / loop_device backing file
info where available).
"""

from __future__ import print_function

import argparse
from collections import defaultdict
import sys

from pykdump.API import *
from LinuxDump.block import get_all_requests
from LinuxDump.fs.dcache import get_pathname

VERSION = "io_trace.py 0.1"

# REQ_OP_* from include/linux/blk_types.h (low 8 bits of cmd_flags)
REQ_OP_MASK = 0xff
REQ_OP_NAMES = {
    0: "READ",
    1: "WRITE",
    2: "FLUSH",
    3: "DISCARD",
    5: "SECURE_ERASE",
    9: "WRITE_ZEROES",
    10: "ZONE_OPEN",
    11: "ZONE_CLOSE",
    12: "ZONE_FINISH",
    13: "ZONE_APPEND",
    15: "ZONE_RESET",
    17: "ZONE_RESET_ALL",
    34: "DRV_IN",
    35: "DRV_OUT",
}


def decode_op(cmd_flags):
    op = int(cmd_flags) & REQ_OP_MASK
    name = REQ_OP_NAMES.get(op, "OP_{}".format(op))
    flags = []
    # Common flag bits in high bits of blk_opf_t
    # Bit 8: FAILFAST_DEV, 9: FAILFAST_TRANSPORT, 10: FAILFAST_DRIVER
    # Bit 11: SYNC, 12: META, 13: PRIO, 15: IDLE, 18: FUA, 19: PREFLUSH
    if cmd_flags & (1 << 11):
        flags.append("SYNC")
    if cmd_flags & (1 << 12):
        flags.append("META")
    if cmd_flags & (1 << 18):
        flags.append("FUA")
    if cmd_flags & (1 << 19):
        flags.append("PREFLUSH")
    return "{}{}".format(name, ("|" + "|".join(flags)) if flags else "")


def sym_name(addr):
    if not addr:
        return "-"
    s = addr2sym(int(addr))
    return s if s else "0x{:x}".format(int(addr))


def dentry_path_best_effort(dentry, vfsmnt=None):
    if not dentry:
        return None
    try:
        if vfsmnt:
            return str(get_pathname(dentry, vfsmnt))
        # Walk d_parent up to root within the superblock
        parts = []
        cur = dentry
        for _ in range(64):
            name = str(cur.d_name.name)
            if name and name != "/":
                parts.append(name)
            parent = cur.d_parent
            if not parent or int(parent) == int(cur):
                break
            cur = parent
        parts.reverse()
        return "/" + "/".join(parts) if parts else "/"
    except Exception:
        try:
            return str(dentry.d_name.name)
        except Exception:
            return None


def inode_first_path(inode):
    try:
        first = inode.i_dentry.first
        if not first:
            return None
        dentry = container_of(first, "struct dentry", "d_u.d_alias")
        return dentry_path_best_effort(dentry)
    except Exception:
        return None


def page_to_folio(page_addr):
    p = readSU("struct page", page_addr)
    try:
        ci = int(p.compound_info)
        if ci & 1:
            return readSU("struct folio", ci - 1)
    except Exception:
        pass
    return readSU("struct folio", page_addr)


def resolve_page_origin(page_addr):
    """Resolve a page/folio to (fstype, s_id, ino, path, folio_index)."""
    if not page_addr or page_addr < 0xffff000000000000:
        return None
    try:
        folio = page_to_folio(page_addr)
        mapping_addr = int(folio.mapping)
        # Bit 0 = anon, Bit 1 = movable/ksm; valid address_space has low 2 bits == 0
        if not mapping_addr or (mapping_addr & 3) != 0 or mapping_addr < 0xffff000000000000:
            return None
        mapping = readSU("struct address_space", mapping_addr)
        if not mapping.host:
            return None
        inode = mapping.host
        ino = int(inode.i_ino)
        sb = inode.i_sb
        fstype = str(sb.s_type.name) if sb and sb.s_type else "?"
        s_id = str(sb.s_id) if sb else "?"
        path = inode_first_path(inode)
        idx = int(folio.index)
        return (fstype, s_id, ino, path, idx)
    except Exception:
        return None


def resolve_bio_origin(bio):
    """Extract end_io symbol, private context (dio/bh), and page/inode origins."""
    end_io_sym = sym_name(bio.bi_end_io)
    extra = []
    origins = []

    try:
        priv = int(bio.bi_private) if bio.bi_private else 0
        if priv and "iomap_dio" in end_io_sym:
            dio = readSU("struct iomap_dio", priv)
            try:
                if dio.iocb and dio.iocb.ki_filp:
                    filp = dio.iocb.ki_filp
                    p = dentry_path_best_effort(filp.f_path.dentry, filp.f_path.mnt)
                    if p:
                        extra.append("dio_file={}".format(p))
            except Exception:
                pass
            try:
                if dio.submit.waiter:
                    t = dio.submit.waiter
                    extra.append("waiter=PID {} ({})".format(int(t.pid), str(t.comm)))
            except Exception:
                pass
        elif priv and "end_bio_bh_io_sync" in end_io_sym:
            bh = readSU("struct buffer_head", priv)
            extra.append("bh_blk={}".format(int(bh.b_blocknr)))
    except Exception:
        pass

    try:
        vcnt = int(bio.bi_vcnt)
        if bio.bi_io_vec and vcnt > 0:
            # Inspect up to 4 bvecs to keep output fast & concise
            for i in range(min(vcnt, 4)):
                bv = bio.bi_io_vec[i]
                if bv.bv_page:
                    orig = resolve_page_origin(int(bv.bv_page))
                    if orig and orig not in origins:
                        origins.append(orig)
    except Exception:
        pass

    return end_io_sym, extra, origins


def get_loop_backing_info(disk):
    """If gendisk is a loop device, return backing file/fs info."""
    try:
        dname = str(disk.disk_name)
        if not dname.startswith("loop") or not disk.private_data:
            return None
        lo = readSU("struct loop_device", int(disk.private_data))
        if not lo.lo_backing_file:
            return str(lo.lo_file_name)
        filp = lo.lo_backing_file
        dentry = filp.f_path.dentry
        mnt = filp.f_path.mnt
        path = dentry_path_best_effort(dentry, mnt)
        inode = dentry.d_inode if dentry else None
        if inode and inode.i_sb:
            fstype = str(inode.i_sb.s_type.name)
            s_id = str(inode.i_sb.s_id)
            return "{} (on {} {}, ino={})".format(path or str(lo.lo_file_name), fstype, s_id, int(inode.i_ino))
        return path or str(lo.lo_file_name)
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(
        prog="io_trace",
        description="End-to-end tracer for in-flight block requests, bios, and filesystem/file origins.",
    )
    parser.add_argument("-d", "--disk", help="Filter by disk name substring (e.g. loop4, vda)")
    parser.add_argument("-m", "--min-age", type=float, default=0.0, help="Only show requests older than N seconds")
    parser.add_argument("-s", "--summary", action="store_true", help="Show summary table only")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Show all bios per request")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    args = parser.parse_args()

    if args.version:
        print(VERSION)
        return

    reqs = list(get_all_requests(""))
    if not reqs:
        print("No in-flight block requests found.")
        return

    records = []
    loop_info_cache = {}

    for req in reqs:
        rinfo = req._reqinfo_
        disk_name = "-"
        disk_obj = None
        try:
            if req.part and req.part.bd_disk:
                disk_obj = req.part.bd_disk
                disk_name = str(disk_obj.disk_name)
            elif req.q and req.q.disk:
                disk_obj = req.q.disk
                disk_name = str(disk_obj.disk_name)
        except Exception:
            pass

        if args.disk and args.disk not in disk_name:
            continue

        age = -float(rinfo.rq_alloc)
        if args.min_age and age < args.min_age:
            continue

        if disk_obj and disk_name not in loop_info_cache:
            linfo = get_loop_backing_info(disk_obj)
            if linfo:
                loop_info_cache[disk_name] = linfo

        bios = []
        b = req.bio
        while b and len(bios) < 64:
            end_io_sym, extra, origins = resolve_bio_origin(b)
            bios.append((int(b), end_io_sym, extra, origins))
            b = b.bi_next

        records.append({
            "req": req,
            "addr": int(req),
            "disk": disk_name,
            "state": str(rinfo.state),
            "age": age,
            "op": decode_op(int(req.cmd_flags)),
            "sector": int(req.__sector),
            "len": int(req.__data_len),
            "tag": int(req.tag),
            "bios": bios,
        })

    if not records:
        print("No matching in-flight block requests.")
        return

    # Summary grouped by (disk, state)
    summary = defaultdict(lambda: {"count": 0, "bytes": 0, "max_age": -1e9, "ops": set()})
    for rec in records:
        key = (rec["disk"], rec["state"])
        s = summary[key]
        s["count"] += 1
        s["bytes"] += rec["len"]
        if rec["age"] > s["max_age"]:
            s["max_age"] = rec["age"]
        s["ops"].add(rec["op"].split("|")[0])

    print("=== In-Flight Block I/O Summary ({} requests) ===".format(len(records)))
    print("{:<12} {:<10} {:>6} {:>10} {:>10}  {}".format("DISK", "STATE", "COUNT", "BYTES", "MAX_AGE", "OPS"))
    for (disk, state), s in sorted(summary.items(), key=lambda kv: kv[1]["max_age"], reverse=True):
        print("{:<12} {:<10} {:>6} {:>10} {:>9.2f}s  {}".format(
            disk, state, s["count"], s["bytes"], s["max_age"], ",".join(sorted(s["ops"]))
        ))

    if loop_info_cache:
        print("\n=== Loopback Backing Files ===")
        for dname, info in sorted(loop_info_cache.items()):
            print("  {:<10} -> {}".format(dname, info))

    if args.summary:
        return

    print("\n=== In-Flight Requests (oldest first) ===")
    records.sort(key=lambda r: r["age"], reverse=True)
    for rec in records:
        sec_str = "-" if rec["sector"] == 0xffffffffffffffff else str(rec["sector"])
        print(
            "[0x{:x}] {:<8} {:<8} age={:>7.2f}s  {:<16} sec={:<10} len={:<7} tag={}".format(
                rec["addr"],
                rec["disk"],
                rec["state"],
                rec["age"],
                rec["op"],
                sec_str,
                rec["len"],
                rec["tag"],
            )
        )
        show_bios = rec["bios"] if args.verbose >= 1 else rec["bios"][:1]
        for baddr, end_sym, extra, origins in show_bios:
            extra_s = ("  " + " ".join(extra)) if extra else ""
            print("    bio 0x{:x} end_io={}{}".format(baddr, end_sym, extra_s))
            for fstype, s_id, ino, path, idx in origins:
                print("      origin: {} ({}) ino={} page_idx={} path={}".format(
                    fstype, s_id, ino, idx, path or "?"
                ))
        if args.verbose == 0 and len(rec["bios"]) > 1:
            print("    ... (+{} more bio(s); use -v to expand)".format(len(rec["bios"]) - 1))


if __name__ == "__main__":
    main()
