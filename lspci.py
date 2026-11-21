#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
pykdump script implementing lspci-like output from kernel PCI structures.
"""

from __future__ import print_function

import argparse
import os
import re
import sys

from pykdump.API import *
from LinuxDump.kobjects import dev_name

VERSION = "lspci.py (pykdump) 0.1"

# Resource flag constants from include/linux/ioport.h
IORESOURCE_IO = 0x00000100
IORESOURCE_MEM = 0x00000200
IORESOURCE_PREFETCH = 0x00002000
IORESOURCE_MEM_64 = 0x00100000
IORESOURCE_DISABLED = 0x10000000
IORESOURCE_ROM_ENABLE = 0x00000002

PCI_ROM_RESOURCE = 6
PCI_BRIDGE_RESOURCES = 7
PCI_NUM_RESOURCES = 17

# Bridge control bits from include/uapi/linux/pci_regs.h
PCI_BRIDGE_CTL_PARITY = 0x01
PCI_BRIDGE_CTL_SERR = 0x02
PCI_BRIDGE_CTL_ISA = 0x04
PCI_BRIDGE_CTL_VGA = 0x08
PCI_BRIDGE_CTL_VGA16 = 0x10
PCI_BRIDGE_CTL_MASTER_ABORT = 0x20
PCI_BRIDGE_CTL_BUS_RESET = 0x40
PCI_BRIDGE_CTL_FAST_BACK = 0x80

PCI_IDS_PATHS = [
    "/usr/share/hwdata/pci.ids",
    "/usr/share/misc/pci.ids",
    "/home/src/pciutils/pci.ids",
]


class PciIdsDB(object):
    """Parser and lookup table for pci.ids."""

    def __init__(self, path=None):
        self.vendors = {}
        self.devices = {}
        self.subsystems = {}
        self.classes = {}
        self.subclasses = {}
        self.progifs = {}
        self.loaded = False

        candidates = [path] if path else PCI_IDS_PATHS
        for p in candidates:
            if p and os.path.isfile(p):
                self._load(p)
                self.loaded = True
                break

    def _load(self, path):
        cur_vendor = None
        cur_device = None
        cur_class = None
        cur_subclass = None
        in_classes = False

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.rstrip("\r\n")
                if not line or line.startswith("#"):
                    continue

                if line.startswith("C "):
                    in_classes = True
                    cur_vendor = None
                    cur_device = None
                    parts = line[2:].strip().split(None, 1)
                    if len(parts) == 2:
                        try:
                            cur_class = int(parts[0], 16)
                            self.classes[cur_class] = parts[1]
                            cur_subclass = None
                        except ValueError:
                            cur_class = None
                    continue

                if in_classes:
                    if line.startswith("\t\t") and cur_class is not None and cur_subclass is not None:
                        parts = line[2:].strip().split(None, 1)
                        if len(parts) == 2:
                            try:
                                progif = int(parts[0], 16)
                                self.progifs[(cur_class, cur_subclass, progif)] = parts[1]
                            except ValueError:
                                pass
                    elif line.startswith("\t") and cur_class is not None:
                        parts = line[1:].strip().split(None, 1)
                        if len(parts) == 2:
                            try:
                                cur_subclass = int(parts[0], 16)
                                self.subclasses[(cur_class, cur_subclass)] = parts[1]
                            except ValueError:
                                cur_subclass = None
                    elif not line.startswith("\t"):
                        in_classes = False
                    else:
                        continue

                if not in_classes:
                    if line.startswith("\t\t") and cur_vendor is not None and cur_device is not None:
                        parts = line[2:].strip().split(None, 2)
                        if len(parts) >= 3:
                            try:
                                svid = int(parts[0], 16)
                                sdid = int(parts[1], 16)
                                self.subsystems[(cur_vendor, cur_device, svid, sdid)] = parts[2]
                            except ValueError:
                                pass
                    elif line.startswith("\t") and cur_vendor is not None:
                        parts = line[1:].strip().split(None, 1)
                        if len(parts) == 2:
                            try:
                                cur_device = int(parts[0], 16)
                                self.devices[(cur_vendor, cur_device)] = parts[1]
                            except ValueError:
                                cur_device = None
                    elif not line.startswith("\t"):
                        parts = line.strip().split(None, 1)
                        if len(parts) == 2:
                            try:
                                cur_vendor = int(parts[0], 16)
                                self.vendors[cur_vendor] = parts[1]
                                cur_device = None
                            except ValueError:
                                cur_vendor = None

    def class_name(self, base_class, subclass):
        name = self.subclasses.get((base_class, subclass))
        if name:
            return name
        name = self.classes.get(base_class)
        if name:
            return "{} [{:02x}{:02x}]".format(name, base_class, subclass)
        return "Class {:02x}{:02x}".format(base_class, subclass)

    def progif_name(self, base_class, subclass, progif):
        return self.progifs.get((base_class, subclass, progif))

    def vendor_name(self, vid):
        return self.vendors.get(vid, "Vendor {:04x}".format(vid))

    def device_name(self, vid, did):
        return self.devices.get((vid, did), "Device {:04x}".format(did))

    def subsys_name(self, vid, did, svid, sdid):
        name = self.subsystems.get((vid, did, svid, sdid))
        if name:
            return name
        return "Device {:04x}".format(sdid)


class PciDeviceInfo(object):
    """Extracted metadata for a single struct pci_dev."""

    def __init__(self, pdev, bus_node):
        self.pdev = pdev
        self.bus_node = bus_node
        self.bus_num = int(pdev.bus.number)
        self.devfn = int(pdev.devfn)
        self.slot = (self.devfn >> 3) & 0x1f
        self.func = self.devfn & 0x7

        dname = str(dev_name(pdev.dev))
        m = re.match(r"^([0-9a-fA-F]+):", dname)
        self.domain = int(m.group(1), 16) if m else 0
        self.full_slot = dname

        self.vendor = int(pdev.vendor) & 0xffff
        self.device = int(pdev.device) & 0xffff
        self.svendor = int(pdev.subsystem_vendor) & 0xffff
        self.sdevice = int(pdev.subsystem_device) & 0xffff
        self.class_id = int(getattr(pdev, "class")) & 0xffffff
        self.base_class = (self.class_id >> 16) & 0xff
        self.subclass = (self.class_id >> 8) & 0xff
        self.progif = self.class_id & 0xff
        self.revision = int(pdev.revision) & 0xff
        self.hdr_type = int(pdev.hdr_type) & 0x7f

        self.irq = int(pdev.irq)
        self.pin = int(pdev.pin)
        self.is_busmaster = bool(pdev.is_busmaster)
        self.msi_enabled = bool(pdev.msi_enabled)
        self.msix_enabled = bool(pdev.msix_enabled)

        self.phys_slot = self._read_phys_slot(pdev)
        self.driver_name = self._read_driver_name(pdev)
        self.resources = self._read_resources(pdev)
        self.subordinate = None

    @staticmethod
    def _read_phys_slot(pdev):
        try:
            if pdev.slot:
                return str(pdev.slot.kobj.name)
        except Exception:
            pass
        return None

    @staticmethod
    def _read_driver_name(pdev):
        try:
            if pdev.driver and pdev.driver.name:
                return str(pdev.driver.name)
        except Exception:
            pass
        return None

    @staticmethod
    def _read_resources(pdev):
        res_list = []
        try:
            for idx in range(PCI_NUM_RESOURCES):
                r = pdev.resource[idx]
                flags = int(r.flags)
                start = int(r.start)
                end = int(r.end)
                res_list.append((idx, start, end, flags))
        except Exception:
            pass
        return res_list

    def bridge_path(self, include_bus=False):
        parts = []
        cur = self
        while cur is not None:
            if include_bus or cur.bus_node.parent is None:
                parts.append("{:02x}:{:02x}.{:x}".format(cur.bus_num, cur.slot, cur.func))
            else:
                parts.append("{:02x}.{:x}".format(cur.slot, cur.func))
            cur = cur.bus_node.self_dev
        parts.reverse()
        return "/".join(parts)

    def format_slot(self, show_domain=False, path_mode=0):
        if path_mode > 0:
            s = self.bridge_path(include_bus=(path_mode > 1))
        else:
            s = "{:02x}:{:02x}.{:x}".format(self.bus_num, self.slot, self.func)
        if show_domain:
            return "{:04x}:{}".format(self.domain, s)
        return s


class PciBusNode(object):
    """Tree node representing a struct pci_bus."""

    def __init__(self, bus, parent=None, self_dev=None):
        self.bus = bus
        self.parent = parent
        self.self_dev = self_dev
        self.number = int(bus.number) & 0xff
        self.primary = int(bus.primary) & 0xff
        self.subordinate_num = int(bus.busn_res.end) & 0xff
        self.bridge_ctl = int(bus.bridge_ctl) & 0xffff
        self.devices = []
        self.children = []
        self.domain = 0


def collect_pci_tree():
    """Walk pci_root_buses and build the bus/device hierarchy."""
    root_buses_head = readSymbol("pci_root_buses")
    root_nodes = []
    all_devs = []

    def walk_bus(bus_su, parent_node=None, self_dev=None):
        bnode = PciBusNode(bus_su, parent=parent_node, self_dev=self_dev)
        for pdev in readSUListFromHead(bus_su.devices, "bus_list", "struct pci_dev"):
            dinfo = PciDeviceInfo(pdev, bnode)
            bnode.domain = dinfo.domain
            bnode.devices.append(dinfo)
            all_devs.append(dinfo)

        bnode.devices.sort(key=lambda d: d.devfn)

        child_map = {}
        for child_bus in readSUListFromHead(bus_su.children, "node", "struct pci_bus"):
            self_ptr = int(child_bus.self) if child_bus.self else 0
            child_self = None
            for d in bnode.devices:
                if int(d.pdev) == self_ptr:
                    child_self = d
                    break
            cnode = walk_bus(child_bus, parent_node=bnode, self_dev=child_self)
            if child_self is not None:
                child_self.subordinate = cnode
            child_map[int(child_bus)] = cnode
            bnode.children.append(cnode)

        bnode.children.sort(key=lambda c: c.number)
        return bnode

    for rbus in readSUListFromHead(root_buses_head, "node", "struct pci_bus"):
        rnode = walk_bus(rbus)
        if not rnode.devices and rnode.children:
            rnode.domain = rnode.children[0].domain
        root_nodes.append(rnode)

    all_devs.sort(key=lambda d: (d.domain, d.bus_num, d.devfn))
    root_nodes.sort(key=lambda b: (b.domain, b.number))
    return root_nodes, all_devs


def parse_hex_or_star(val):
    if not val or val == "*":
        return None
    return int(val, 16)


def parse_slot_filter(spec):
    """Parse -s [[[[<domain>]:]<bus>]:][<device>][.[<func>]]."""
    if not spec:
        return None
    dom = bus = dev = func = None
    if "." in spec:
        left, fpart = spec.rsplit(".", 1)
        func = parse_hex_or_star(fpart)
    else:
        left = spec

    parts = left.split(":")
    if len(parts) == 1:
        dev = parse_hex_or_star(parts[0])
    elif len(parts) == 2:
        bus = parse_hex_or_star(parts[0])
        dev = parse_hex_or_star(parts[1])
    elif len(parts) == 3:
        dom = parse_hex_or_star(parts[0])
        bus = parse_hex_or_star(parts[1])
        dev = parse_hex_or_star(parts[2])
    else:
        raise ValueError("Invalid slot specification: {}".format(spec))

    return (dom, bus, dev, func)


def parse_device_filter(spec):
    """Parse -d [<vendor>]:[<device>][:<class>[:<prog-if>]]."""
    if not spec:
        return None
    parts = spec.split(":")
    if len(parts) < 2 or len(parts) > 4:
        raise ValueError("Invalid device specification: {}".format(spec))
    vid = parse_hex_or_star(parts[0])
    did = parse_hex_or_star(parts[1])
    cls_pattern = None
    progif = None
    if len(parts) >= 3 and parts[2] and parts[2] != "*":
        cstr = parts[2].lower()
        if not re.match(r"^[0-9a-fx]{1,4}$", cstr):
            raise ValueError("Invalid class specification: {}".format(parts[2]))
        cls_pattern = cstr.rjust(4, "0")
    if len(parts) == 4:
        progif = parse_hex_or_star(parts[3])
    return (vid, did, cls_pattern, progif)


def matches_filters(dinfo, slot_flt, dev_flt):
    if slot_flt:
        dom, bus, dev, func = slot_flt
        if dom is not None and dinfo.domain != dom:
            return False
        if bus is not None and dinfo.bus_num != bus:
            return False
        if dev is not None and dinfo.slot != dev:
            return False
        if func is not None and dinfo.func != func:
            return False
    if dev_flt:
        vid, did, cls_pat, progif = dev_flt
        if vid is not None and dinfo.vendor != vid:
            return False
        if did is not None and dinfo.device != did:
            return False
        if cls_pat is not None:
            actual_cls = "{:02x}{:02x}".format(dinfo.base_class, dinfo.subclass)
            for a, p in zip(actual_cls, cls_pat):
                if p != "x" and a != p:
                    return False
        if progif is not None and dinfo.progif != progif:
            return False
    return True


def format_size(size):
    if size >= (1 << 30) and size % (1 << 30) == 0:
        return "{}G".format(size >> 30)
    if size >= (1 << 20) and size % (1 << 20) == 0:
        return "{}M".format(size >> 20)
    if size >= (1 << 10) and size % (1 << 10) == 0:
        return "{}K".format(size >> 10)
    return str(size)


def format_header_line(dinfo, db, args, show_domain, path_mode):
    slot_str = dinfo.format_slot(show_domain=show_domain, path_mode=path_mode)
    cls_hex = "{:02x}{:02x}".format(dinfo.base_class, dinfo.subclass)

    if args.n == 1:
        cls_str = cls_hex
        dev_str = "{:04x}:{:04x}".format(dinfo.vendor, dinfo.device)
    elif args.n >= 2:
        raw_cls = db.class_name(dinfo.base_class, dinfo.subclass)
        cls_str = raw_cls if raw_cls.endswith("[{}]".format(cls_hex)) else "{} [{}]".format(raw_cls, cls_hex)
        dev_str = "{} {} [{:04x}:{:04x}]".format(
            db.vendor_name(dinfo.vendor),
            db.device_name(dinfo.vendor, dinfo.device),
            dinfo.vendor,
            dinfo.device,
        )
    else:
        cls_str = db.class_name(dinfo.base_class, dinfo.subclass)
        dev_str = "{} {}".format(
            db.vendor_name(dinfo.vendor),
            db.device_name(dinfo.vendor, dinfo.device),
        )

    line = "{} {}: {}".format(slot_str, cls_str, dev_str)
    if dinfo.revision:
        line += " (rev {:02x})".format(dinfo.revision)

    if args.v >= 1:
        pname = db.progif_name(dinfo.base_class, dinfo.subclass, dinfo.progif)
        if pname or dinfo.progif:
            if pname and args.n != 1:
                line += " (prog-if {:02x} [{}])".format(dinfo.progif, pname)
            else:
                line += " (prog-if {:02x})".format(dinfo.progif)
    return line


def format_resource_line(idx, start, end, flags, verbose):
    if not flags:
        return None
    size = end - start + 1 if end >= start else 0
    disabled = bool(flags & IORESOURCE_DISABLED)

    if idx == PCI_ROM_RESOURCE:
        prefix = "\tExpansion ROM at "
        rom_disabled = disabled or not (flags & IORESOURCE_ROM_ENABLE)
        if start == 0 and rom_disabled and verbose < 3:
            return None
        addr_str = "{:08x}".format(start)
        parts = [prefix + addr_str]
        if rom_disabled:
            parts.append("[disabled]")
        if size:
            parts.append("[size={}]".format(format_size(size)))
        return " ".join(parts)

    if idx >= PCI_BRIDGE_RESOURCES:
        return None

    prefix = "\tRegion {}: ".format(idx) if verbose >= 2 else "\t"
    if flags & IORESOURCE_IO:
        addr_str = "{:04x}".format(start)
        parts = ["{}I/O ports at {}".format(prefix, addr_str)]
        if disabled:
            parts.append("[disabled]")
        if size:
            parts.append("[size={}]".format(format_size(size)))
        return " ".join(parts)

    if flags & IORESOURCE_MEM:
        width = "64-bit" if (flags & IORESOURCE_MEM_64) else "32-bit"
        pref = "prefetchable" if (flags & IORESOURCE_PREFETCH) else "non-prefetchable"
        addr_str = "{:08x}".format(start)
        parts = ["{}Memory at {} ({}, {})".format(prefix, addr_str, width, pref)]
        if disabled:
            parts.append("[disabled]")
        if size:
            parts.append("[size={}]".format(format_size(size)))
        return " ".join(parts)

    return None


def format_bridge_windows(dinfo, verbose):
    lines = []
    sub = dinfo.subordinate
    if not sub:
        return lines

    lines.append(
        "\tBus: primary={:02x}, secondary={:02x}, subordinate={:02x}".format(
            dinfo.bus_num, sub.number, sub.subordinate_num
        )
    )

    for idx in range(PCI_BRIDGE_RESOURCES, PCI_BRIDGE_RESOURCES + 3):
        if idx >= len(dinfo.resources):
            break
        _, start, end, flags = dinfo.resources[idx]
        if not flags or (flags & IORESOURCE_DISABLED) or end < start:
            continue
        size = end - start + 1
        if flags & IORESOURCE_IO:
            lines.append(
                "\tI/O behind bridge: {:04x}-{:04x} [size={}]".format(
                    start, end, format_size(size)
                )
            )
        elif flags & IORESOURCE_MEM:
            label = (
                "Prefetchable memory behind bridge"
                if (flags & IORESOURCE_PREFETCH)
                else "Memory behind bridge"
            )
            lines.append(
                "\t{}: {:08x}-{:08x} [size={}]".format(
                    label, start, end, format_size(size)
                )
            )

    if verbose >= 2:
        ctl = sub.bridge_ctl
        ctl_flags = [
            ("Parity", PCI_BRIDGE_CTL_PARITY),
            ("SERR", PCI_BRIDGE_CTL_SERR),
            ("NoISA", PCI_BRIDGE_CTL_ISA),
            ("VGA", PCI_BRIDGE_CTL_VGA),
            ("VGA16", PCI_BRIDGE_CTL_VGA16),
            ("MAbort", PCI_BRIDGE_CTL_MASTER_ABORT),
            ("Reset", PCI_BRIDGE_CTL_BUS_RESET),
            ("FastB2B", PCI_BRIDGE_CTL_FAST_BACK),
        ]
        ctl_str = " ".join(
            "{}{}".format(name, "+" if (ctl & bit) else "-") for name, bit in ctl_flags
        )
        lines.append("\tBridgeCtl: {}".format(ctl_str))

    return lines


def format_capabilities(dinfo):
    lines = []
    pdev = dinfo.pdev
    cap_fields = [
        ("pm_cap", "Power Management"),
        ("msi_cap", "MSI"),
        ("msix_cap", "MSI-X"),
        ("pcie_cap", "Express"),
        ("aer_cap", "Advanced Error Reporting"),
        ("acs_cap", "Access Control Services"),
        ("dpc_cap", "Downstream Port Containment"),
        ("ats_cap", "Address Translation Service (ATS)"),
        ("pri_cap", "Page Request Interface (PRI)"),
        ("pasid_cap", "Process Address Space ID (PASID)"),
        ("ptm_cap", "Precision Time Measurement"),
        ("rebar_cap", "Resizable BAR"),
        ("tph_cap", "Transaction Processing Hints"),
    ]
    caps = []
    for field, label in cap_fields:
        try:
            off = int(getattr(pdev, field))
            if off:
                extra = ""
                if field == "msi_cap":
                    extra = ": Enable{}".format("+" if dinfo.msi_enabled else "-")
                elif field == "msix_cap":
                    extra = ": Enable{}".format("+" if dinfo.msix_enabled else "-")
                caps.append((off, "\tCapabilities: [{:02x}] {}{}".format(off, label, extra)))
        except Exception:
            pass
    caps.sort(key=lambda x: x[0])
    for _, line in caps:
        lines.append(line)
    return lines


def print_normal_devices(devs, db, args, show_domain, path_mode):
    show_kernel = args.k or (args.v >= 1)
    for i, dinfo in enumerate(devs):
        print(format_header_line(dinfo, db, args, show_domain, path_mode))

        if (args.v >= 1 or args.k) and (dinfo.svendor or dinfo.sdevice):
            if args.n == 1:
                print("\tSubsystem: {:04x}:{:04x}".format(dinfo.svendor, dinfo.sdevice))
            elif args.n >= 2:
                print(
                    "\tSubsystem: {} {} [{:04x}:{:04x}]".format(
                        db.vendor_name(dinfo.svendor),
                        db.subsys_name(dinfo.vendor, dinfo.device, dinfo.svendor, dinfo.sdevice),
                        dinfo.svendor,
                        dinfo.sdevice,
                    )
                )
            else:
                print(
                    "\tSubsystem: {} {}".format(
                        db.vendor_name(dinfo.svendor),
                        db.subsys_name(dinfo.vendor, dinfo.device, dinfo.svendor, dinfo.sdevice),
                    )
                )

        if args.v >= 1:
            if dinfo.phys_slot:
                print("\tPhysical Slot: {}".format(dinfo.phys_slot))

            if args.v >= 2:
                print(
                    "\tControl: BusMaster{}".format("+" if dinfo.is_busmaster else "-")
                )
                if dinfo.pin or dinfo.irq:
                    pin_chr = chr(ord("A") + dinfo.pin - 1) if 1 <= dinfo.pin <= 4 else "?"
                    if dinfo.pin:
                        print("\tInterrupt: pin {} routed to IRQ {}".format(pin_chr, dinfo.irq))
                    elif dinfo.irq:
                        print("\tInterrupt: routed to IRQ {}".format(dinfo.irq))
            else:
                flags = []
                if dinfo.is_busmaster:
                    flags.append("bus master")
                if dinfo.irq:
                    flags.append("IRQ {}".format(dinfo.irq))
                if flags:
                    print("\tFlags: {}".format(", ".join(flags)))

            for idx, start, end, rflags in dinfo.resources:
                rline = format_resource_line(idx, start, end, rflags, args.v)
                if rline:
                    print(rline)

            if dinfo.hdr_type == 1:
                for bline in format_bridge_windows(dinfo, args.v):
                    print(bline)

            for cline in format_capabilities(dinfo):
                print(cline)

        if show_kernel and dinfo.driver_name:
            print("\tKernel driver in use: {}".format(dinfo.driver_name))

        if args.v >= 1 and i < len(devs) - 1:
            print()


def print_machine_simple(devs, db, args, show_domain, path_mode):
    for dinfo in devs:
        slot_str = dinfo.format_slot(show_domain=show_domain, path_mode=path_mode)
        if args.n >= 1:
            cls_s = "{:02x}{:02x}".format(dinfo.base_class, dinfo.subclass)
            ven_s = "{:04x}".format(dinfo.vendor)
            dev_s = "{:04x}".format(dinfo.device)
            sven_s = "{:04x}".format(dinfo.svendor) if (dinfo.svendor or dinfo.sdevice) else ""
            sdev_s = "{:04x}".format(dinfo.sdevice) if (dinfo.svendor or dinfo.sdevice) else ""
        else:
            cls_s = db.class_name(dinfo.base_class, dinfo.subclass)
            ven_s = db.vendor_name(dinfo.vendor)
            dev_s = db.device_name(dinfo.vendor, dinfo.device)
            if dinfo.svendor or dinfo.sdevice:
                sven_s = db.vendor_name(dinfo.svendor)
                sdev_s = db.subsys_name(dinfo.vendor, dinfo.device, dinfo.svendor, dinfo.sdevice)
            else:
                sven_s = ""
                sdev_s = ""

        fields = [
            slot_str,
            '"{}"'.format(cls_s),
            '"{}"'.format(ven_s),
            '"{}"'.format(dev_s),
        ]
        if dinfo.revision:
            fields.append("-r{:02x}".format(dinfo.revision))
        fields.append("-p{:02x}".format(dinfo.progif))
        fields.append('"{}"'.format(sven_s))
        fields.append('"{}"'.format(sdev_s))
        print(" ".join(fields))


def print_machine_verbose(devs, db, args, show_domain, path_mode):
    for i, dinfo in enumerate(devs):
        slot_str = dinfo.format_slot(show_domain=show_domain, path_mode=path_mode)
        tag = "Slot" if args.m >= 2 else "Device"
        print("{}:\t{}".format(tag, slot_str))
        if args.n >= 1:
            print("Class:\t{:02x}{:02x}".format(dinfo.base_class, dinfo.subclass))
            print("Vendor:\t{:04x}".format(dinfo.vendor))
            print("Device:\t{:04x}".format(dinfo.device))
            if dinfo.svendor or dinfo.sdevice:
                print("SVendor:\t{:04x}".format(dinfo.svendor))
                print("SDevice:\t{:04x}".format(dinfo.sdevice))
        else:
            print("Class:\t{}".format(db.class_name(dinfo.base_class, dinfo.subclass)))
            print("Vendor:\t{}".format(db.vendor_name(dinfo.vendor)))
            print("Device:\t{}".format(db.device_name(dinfo.vendor, dinfo.device)))
            if dinfo.svendor or dinfo.sdevice:
                print("SVendor:\t{}".format(db.vendor_name(dinfo.svendor)))
                print(
                    "SDevice:\t{}".format(
                        db.subsys_name(dinfo.vendor, dinfo.device, dinfo.svendor, dinfo.sdevice)
                    )
                )
        if dinfo.revision:
            print("Rev:\t{:02x}".format(dinfo.revision))
        print("ProgIf:\t{:02x}".format(dinfo.progif))
        if dinfo.phys_slot:
            print("PhySlot:\t{}".format(dinfo.phys_slot))
        if args.k and dinfo.driver_name:
            print("Driver:\t{}".format(dinfo.driver_name))
        if i < len(devs) - 1:
            print()


def print_tree(root_nodes, db, args):
    def render_bus(bnode, prefix, is_root=False):
        if is_root:
            head = "-[{:04x}:{:02x}]-".format(bnode.domain, bnode.number)
            cur_prefix = " " * len(head)
        else:
            head = "-[{:02x}]-".format(bnode.number)
            cur_prefix = prefix + " " * len(head)

        if not bnode.devices:
            print("{}-".format(head))
            return

        for idx, dinfo in enumerate(bnode.devices):
            first = idx == 0
            last = idx == len(bnode.devices) - 1
            if len(bnode.devices) == 1:
                branch = "---"
                child_cont = "   "
            elif first:
                branch = "+-"
                child_cont = "| "
            elif last:
                branch = "\\-"
                child_cont = "  "
            else:
                branch = "+-"
                child_cont = "| "

            dev_str = "{:02x}.{:x}".format(dinfo.slot, dinfo.func)
            lead = head if first else cur_prefix
            line_prefix = "{}{}{}".format(lead, branch, dev_str)

            if dinfo.subordinate is not None:
                sys.stdout.write(line_prefix)
                render_bus(dinfo.subordinate, cur_prefix + child_cont + " " * len(dev_str), is_root=False)
            else:
                if args.v >= 1:
                    desc = "  {} {}".format(
                        db.vendor_name(dinfo.vendor),
                        db.device_name(dinfo.vendor, dinfo.device),
                    )
                    print("{}{}".format(line_prefix, desc))
                else:
                    print(line_prefix)

    for rnode in root_nodes:
        render_bus(rnode, "", is_root=True)


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="lspci",
        description="Display PCI buses and devices from a Linux vmcore (lspci clone).",
        add_help=True,
    )
    parser.add_argument("-m", action="count", default=0, help="Machine-readable output (-m, -mm)")
    parser.add_argument("-t", action="store_true", help="Show bus tree")
    parser.add_argument("-v", action="count", default=0, help="Be verbose (-v, -vv, -vvv)")
    parser.add_argument("-k", action="store_true", help="Show kernel drivers handling each device")
    parser.add_argument("-b", action="store_true", help="Bus-centric view (kernel-mapped values in vmcore)")
    parser.add_argument("-D", action="store_true", help="Always show PCI domain numbers")
    parser.add_argument("-P", action="count", default=0, help="Identify devices by bridge path (-P, -PP)")
    parser.add_argument("-n", action="count", default=0, help="Show numeric IDs (-n) or both (-nn)")
    parser.add_argument("-s", dest="slot_filter", help="Show only devices in specified slot")
    parser.add_argument("-d", dest="dev_filter", help="Show only devices with specified vendor/device/class")
    parser.add_argument("-i", dest="ids_file", help="Use specified pci.ids file")
    parser.add_argument("-x", action="count", default=0, help="Hex dump of config space (unavailable in vmcore)")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.version:
        print(VERSION)
        return

    if args.x:
        print("Note: raw PCI config space (-x) is not stored in vmcore.", file=sys.stderr)

    try:
        slot_flt = parse_slot_filter(args.slot_filter)
        dev_flt = parse_device_filter(args.dev_filter)
    except ValueError as exc:
        print("lspci: {}".format(exc), file=sys.stderr)
        sys.exit(1)

    db = PciIdsDB(args.ids_file)
    root_nodes, all_devs = collect_pci_tree()

    domains = set(d.domain for d in all_devs)
    show_domain = args.D or (len(domains) > 1)

    filtered_devs = [d for d in all_devs if matches_filters(d, slot_flt, dev_flt)]

    if args.t:
        print_tree(root_nodes, db, args)
    elif args.m >= 1 and args.v == 0:
        print_machine_simple(filtered_devs, db, args, show_domain, args.P)
    elif args.m >= 1 and args.v >= 1:
        print_machine_verbose(filtered_devs, db, args, show_domain, args.P)
    else:
        print_normal_devices(filtered_devs, db, args, show_domain, args.P)


if __name__ == "__main__":
    main()
