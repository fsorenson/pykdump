#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
pykdump implementation of 'kmem -S' for Linux 7.1+ SLUB kernels with cpu_sheaves.

Walks per-node kmem_cache_node partial/full slab lists, decodes slab freelists
(including CONFIG_SLAB_FREELIST_HARDENED), and inspects per-CPU slub_percpu_sheaves
and node_barn sheaves to classify objects as active (in use) vs inactive (free).
"""

from __future__ import print_function

import argparse
import sys

from pykdump.API import *
from LinuxDump import percpu

VERSION = "kmem_S.py 0.1"


def swab64(x):
    return int.from_bytes((x & 0xffffffffffffffff).to_bytes(8, "little"), "big")


def get_page_virt_fns():
    page_sz = struct_size("struct page")
    if symbol_exists("vmemmap_base") and symbol_exists("page_offset_base"):
        vmemmap_base = int(readSymbol("vmemmap_base"))
        page_offset_base = int(readSymbol("page_offset_base"))

        def p2v(page_addr):
            pfn = (page_addr - vmemmap_base) // page_sz
            return page_offset_base + (pfn << 12)

        def v2p(vaddr):
            pfn = (vaddr - page_offset_base) >> 12
            return vmemmap_base + pfn * page_sz

        return p2v, v2p

    def p2v_crash(page_addr):
        out = exec_crash_command("kmem -p 0x{:x}".format(page_addr))
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].lower().endswith(hex(page_addr)[2:].lower()):
                paddr = int(parts[1], 16)
                return paddr + 0xffff888000000000
        return 0

    return p2v_crash, None


def find_kmem_cache(target):
    slab_caches_addr = sym2addr("slab_caches")
    if not slab_caches_addr:
        raise RuntimeError("Symbol 'slab_caches' not found")

    if target.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in target):
        try:
            addr = int(target, 16)
            if addr > 0xffff000000000000:
                return readSU("struct kmem_cache", addr)
        except ValueError:
            pass

    for c in readSUListFromHead(slab_caches_addr, "list", "struct kmem_cache"):
        if str(c.name) == target:
            return c
    return None


def decode_freepointer(cache_random, ptr_addr, raw_val):
    if not raw_val:
        return 0
    if cache_random:
        return (raw_val ^ cache_random ^ swab64(ptr_addr)) & 0xffffffffffffffff
    return raw_val & 0xffffffffffffffff


def collect_slab_freelist(slab, cache_random, offset, slab_vaddr, slab_bytes):
    """Return set of free object addresses on slab's freelist."""
    free_objs = set()
    try:
        cur = int(slab.freelist)
    except Exception:
        return free_objs

    seen = set()
    limit = 4096
    while cur and cur not in seen and len(seen) < limit:
        if cur < slab_vaddr or cur >= slab_vaddr + slab_bytes:
            break
        seen.add(cur)
        free_objs.add(cur)
        ptr_addr = cur + offset
        try:
            raw = readU64(ptr_addr)
        except Exception:
            break
        cur = decode_freepointer(cache_random, ptr_addr, raw)
    return free_objs


def collect_sheaf_objects(sheaf_ptr):
    objs = set()
    if not sheaf_ptr:
        return objs
    try:
        sh = readSU("struct slab_sheaf", int(sheaf_ptr))
        cnt = int(sh.size)
        for i in range(min(cnt, 4096)):
            addr = int(sh.objects[i])
            if addr:
                objs.add(addr)
    except Exception:
        pass
    return objs


def collect_cache_sheaves(cache):
    """Collect all object addresses currently cached as free in cpu_sheaves and node_barns."""
    sheaf_free = set()
    percpu_sheaves_info = []

    if cache.hasField("cpu_sheaves") and cache.cpu_sheaves:
        base_ptr = int(cache.cpu_sheaves)
        for cpu in range(sys_info.CPUS):
            try:
                pcpu_addr = (base_ptr + percpu.per_cpu_offsets[cpu]) & 0xffffffffffffffff
                ps = readSU("struct slub_percpu_sheaves", pcpu_addr)
                main_objs = collect_sheaf_objects(ps.main)
                spare_objs = collect_sheaf_objects(ps.spare)
                rcu_objs = collect_sheaf_objects(ps.rcu_free)
                sheaf_free.update(main_objs)
                sheaf_free.update(spare_objs)
                sheaf_free.update(rcu_objs)
                if main_objs or spare_objs or rcu_objs:
                    percpu_sheaves_info.append((cpu, len(main_objs), len(spare_objs), len(rcu_objs)))
            except Exception:
                pass

    barn_count = 0
    if cache.hasField("per_node"):
        for nid in range(1024):
            try:
                pn = cache.per_node[nid]
                if not pn.node:
                    break
                if pn.barn:
                    barn = pn.barn
                    for sh in readSUListFromHead(int(barn.sheaves_full), "barn_list", "struct slab_sheaf", warn=False):
                        objs = collect_sheaf_objects(sh)
                        sheaf_free.update(objs)
                        barn_count += len(objs)
            except Exception:
                break

    return sheaf_free, percpu_sheaves_info, barn_count


def main():
    parser = argparse.ArgumentParser(
        prog="kmem_S",
        description="Inspect SLUB kmem_cache slabs and active/inactive objects (Linux 7.1+ sheaves).",
    )
    parser.add_argument("cache", help="kmem_cache name (e.g. dentry) or hex address")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-a", "--active", action="store_true", help="Print only active (allocated) object addresses")
    group.add_argument("-i", "--inactive", "--free", action="store_true", help="Print only inactive (free) object addresses")
    parser.add_argument("-q", "--addresses-only", action="store_true", help="Print object addresses only, one per line")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    args = parser.parse_args()

    if args.version:
        print(VERSION)
        return

    cache = find_kmem_cache(args.cache)
    if not cache:
        print("kmem_cache '{}' not found.".format(args.cache), file=sys.stderr)
        sys.exit(1)

    p2v, v2p = get_page_virt_fns()
    obj_size = int(cache.size)
    raw_obj_size = int(cache.object_size)
    offset = int(cache.offset)
    red_left_pad = int(cache.red_left_pad) if cache.hasField("red_left_pad") else 0
    cache_random = int(cache.random) if cache.hasField("random") else 0
    order = (int(cache.oo.x) >> 16) & 0xffff
    max_oo_objs = int(cache.oo.x) & 0xffff
    slab_bytes = PAGESIZE << order

    sheaf_free, percpu_sheaves_info, barn_count = collect_cache_sheaves(cache)

    nodes = []
    if cache.hasField("per_node"):
        for nid in range(1024):
            pn = cache.per_node[nid]
            if not pn.node:
                break
            nodes.append((nid, pn.node))
    elif cache.hasField("node"):
        for nid in range(1024):
            nd = cache.node[nid]
            if not nd:
                break
            nodes.append((nid, nd))

    total_slabs = 0
    total_active = 0
    total_inactive = 0
    slab_records = []
    seen_slabs = set()

    def process_slab(nid, list_name, slab):
        nonlocal total_slabs, total_active, total_inactive
        slab_addr = int(slab)
        if slab_addr in seen_slabs:
            return
        seen_slabs.add(slab_addr)
        total_slabs += 1
        slab_vaddr = p2v(slab_addr)
        # slab.objects is a 15-bit bitfield inside counters
        num_objs = int(slab.objects) & 0x7fff
        if num_objs == 0 or num_objs > max_oo_objs:
            num_objs = max_oo_objs
        freelist_objs = collect_slab_freelist(slab, cache_random, offset, slab_vaddr, slab_bytes)

        active_list = []
        inactive_list = []
        for idx in range(num_objs):
            obj_addr = slab_vaddr + idx * obj_size + red_left_pad
            if obj_addr in freelist_objs or obj_addr in sheaf_free:
                inactive_list.append(obj_addr)
            else:
                active_list.append(obj_addr)

        total_active += len(active_list)
        total_inactive += len(inactive_list)
        slab_records.append((nid, list_name, slab_addr, slab_vaddr, num_objs, active_list, inactive_list))

    for nid, nd in nodes:
        for list_name, list_head in [("partial", nd.partial), ("full", nd.full)]:
            for slab in readSUListFromHead(int(list_head), "slab_list", "struct slab", warn=False):
                process_slab(nid, list_name, slab)

    # Discover additional full slabs referenced by objects cached in sheaves
    if v2p is not None:
        for obj_addr in sorted(sheaf_free):
            slab_vaddr = obj_addr & ~(slab_bytes - 1)
            slab_addr = v2p(slab_vaddr)
            if slab_addr not in seen_slabs:
                try:
                    slab = readSU("struct slab", slab_addr)
                    if int(slab.slab_cache) == int(cache):
                        process_slab(0, "sheaf_slab", slab)
                except Exception:
                    pass

    if not args.addresses_only:
        print("CACHE: {} <struct kmem_cache 0x{:x}>  objsize={}  size={}  order={}".format(
            str(cache.name), int(cache), raw_obj_size, obj_size, order
        ))
        print("SLABS: {} (on node partial/full lists)  ACTIVE: {}  INACTIVE: {} (sheaf_cached={} barn_cached={})".format(
            total_slabs, total_active, total_inactive, len(sheaf_free) - barn_count, barn_count
        ))
        if percpu_sheaves_info and not (args.active or args.inactive):
            print("CPU SHEAVES (main/spare/rcu_free): " + ", ".join(
                "cpu{}:{}/{}/{}".format(c, m, s, r) for c, m, s, r in percpu_sheaves_info
            ))
        print()

    for nid, list_name, slab_addr, slab_vaddr, num_objs, active_list, inactive_list in slab_records:
        if args.active:
            chosen = [(a, True) for a in active_list]
        elif args.inactive:
            chosen = [(a, False) for a in inactive_list]
        else:
            chosen = [(a, a in active_list) for a in sorted(active_list + inactive_list)]

        if not chosen:
            continue

        if not args.addresses_only:
            print("SLAB 0x{:x} (vaddr 0x{:x}, node={}, list={}, objects={}, active={}, inactive={}):".format(
                slab_addr, slab_vaddr, nid, list_name, num_objs, len(active_list), len(inactive_list)
            ))
        for addr, is_act in chosen:
            if args.addresses_only:
                print("0x{:x}".format(addr))
            else:
                print("  0x{:016x}  {}".format(addr, "[ACTIVE]" if is_act else "[FREE]"))


if __name__ == "__main__":
    main()
