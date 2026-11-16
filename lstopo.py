#!/usr/bin/python

from __future__ import print_function

import sys
import os

mypath = os.path.dirname(os.path.realpath(sys.argv[0] if sys.argv else __file__))
if mypath and mypath not in sys.path:
	sys.path.insert(0, mypath)

from sorenson_lib import val_to_units_string

if __name__ == "__main__":
	mypath = os.path.dirname(os.path.realpath(sys.argv[0]))
	check_paths = [mypath, "/cores/crashext/epython/"]
	for p in check_paths:
		if os.path.isdir(p):
			if p not in sys.path:
				sys.path.append(p)

from pykdump.API import *
from LinuxDump.Tasks import TaskTable
from LinuxDump.inet.proto import *
from LinuxDump import percpu

def get_all_cpus():
	cpus = {}

	addrs = percpu.get_cpu_var("cpu_sys_devices")
	for cpu, a in enumerate(addrs):

		dev_addr = readSU("struct device", readPtr(a))
		cpu_addr = container_of(dev_addr, "struct cpu", "dev")

		cpus[cpu] = cpu_addr
	return cpus

def cpumask_to_str(cpumask):
	cpus = []
	for word_idx, word in enumerate(cpumask.bits):
		w = int(word)
		if not w:
			continue
		base = word_idx * 64
		while w:
			lsb = w & -w
			cpus.append(base + lsb.bit_length() - 1)
			w ^= lsb
	if not cpus:
		return ""
	ranges = []
	start = prev = cpus[0]
	for c in cpus[1:]:
		if c == prev + 1:
			prev = c
		else:
			ranges.append(str(start) if start == prev else "{}-{}".format(start, prev))
			start = prev = c
	ranges.append(str(start) if start == prev else "{}-{}".format(start, prev))
	return ",".join(ranges)

def cache_type_str(ctype):
	cval = int(ctype)
	return {
		0: "NoCache",
		1: "Instruction",
		2: "Data",
		3: "Separate",
		4: "Unified",
	}.get(cval, "Type({})".format(cval))

def print_cpu_cacheinfo(ci_addrs, cpunum, indent="\t     "):
	if ci_addrs is None or cpunum >= len(ci_addrs):
		return
	ci = readSU("struct cpu_cacheinfo", ci_addrs[cpunum])
	for i in range(ci.num_leaves):
		leaf = ci.info_list[i]
		size_str = val_to_units_string(leaf.size, 1024) if leaf.size else "0"
		shared_str = cpumask_to_str(leaf.shared_cpu_map)
		print("{}L{} {} {} (ways={}, sets={}, line={}B, shared_cpus={})".format(
			indent, leaf.level, cache_type_str(leaf.type), size_str,
			leaf.ways_of_associativity, leaf.number_of_sets,
			leaf.coherency_line_size, shared_str))

def get_numa_info(num_cpus):
	cpu_to_node = {}
	node_meminfo = {}
	pagesize = getattr(sys_info, "PAGESIZE", 4096)

	if symbol_exists("numa_node"):
		numa_addrs = percpu.get_cpu_var("numa_node")
		for cpu in range(min(num_cpus, len(numa_addrs))):
			cpu_to_node[cpu] = readInt(numa_addrs[cpu])
	else:
		cpus = get_all_cpus()
		for cpu, cobj in cpus.items():
			cpu_to_node[cpu] = int(cobj.node_id)

	if symbol_exists("node_data"):
		node_data = readSymbol("node_data")
		if symbol_exists("nr_node_ids"):
			node_ids = range(int(readSymbol("nr_node_ids")))
		else:
			node_ids = sorted(set(cpu_to_node.values()))
		for nid in node_ids:
			if nid < 0:
				continue
			pgdat = node_data[nid]
			if not pgdat:
				continue
			node_meminfo[nid] = {
				'present': int(pgdat.node_present_pages) * pagesize,
				'spanned': int(pgdat.node_spanned_pages) * pagesize,
			}

	return cpu_to_node, node_meminfo

def get_all_cpuinfo():
	cpuinfo = {}

	addrs = percpu.get_cpu_var("cpu_info")
	for cpu, a in enumerate(addrs):

		info = readSU("struct cpuinfo_x86", a)
		cpuinfo[cpu] = info
	return cpuinfo

def get_all_rh_cpuinfo():
	if not symbol_exists("rh_cpu_info"):
		return {}
	rh_cpuinfo = {}

	addrs = percpu.get_cpu_var("rh_cpu_info")
	for cpu, a in enumerate(addrs):
		info = readSU("struct rh_cpuinfo_x86", a)
		rh_cpuinfo[cpu] = info
	return rh_cpuinfo


def get_cpu_pkg_core(cpuinfo):
	if cpuinfo.hasField("topo"):
		return cpuinfo.topo.pkg_id, cpuinfo.topo.core_id
	return cpuinfo.phys_proc_id, cpuinfo.cpu_core_id


def show_cpuinfo():
	all_cpuinfo = get_all_cpuinfo()

	proc_cpuinfo = {}
	topology = {}

	for num in all_cpuinfo:
		cpuinfo = all_cpuinfo[num]
		cpunum = cpuinfo.cpu_index
		phys_proc_id, cpu_core_id = get_cpu_pkg_core(cpuinfo)

		topology.setdefault(phys_proc_id, {}).setdefault(cpu_core_id, []).append(cpunum)

		entry = {
			'vendor': cpuinfo.x86_vendor_id,
			'model': cpuinfo.x86_model_id,
			'family': int(cpuinfo.x86),
			'model_num': int(cpuinfo.x86_model),
			'stepping': int(cpuinfo.x86_stepping),
			'speed': "{:.3f}".format(cpuinfo.loops_per_jiffy / 1000),
			'physical_id': phys_proc_id,
			'core_id': cpu_core_id,
		}
		if cpuinfo.hasField("microcode"):
			entry['microcode'] = int(cpuinfo.microcode)
		proc_cpuinfo[cpunum] = entry

	phys_ids = [ e for e in topology ]

	ci_addrs = percpu.get_cpu_var("ci_cpu_cacheinfo") if symbol_exists("ci_cpu_cacheinfo") else None
	cpu_to_node, node_meminfo = get_numa_info(len(all_cpuinfo))

	for phys_id in phys_ids:
		core_ids = [ e for e in topology[phys_id] ]
		core_id0 = core_ids[0]
		sample_thread_ids = [ e for e in topology[phys_id][core_id0] ]
		num_threads = len(sample_thread_ids)
		sample_cpu = sample_thread_ids[0]
		sample = proc_cpuinfo[sample_cpu]

		print("Socket {}: {}-core".format(phys_id, len(core_ids)), end='')
		if num_threads > 1:
			print(", {} thread/core".format(num_threads), end='')

		print(" '{}' @ {} MHz".format(sample['vendor'], sample['speed']), end='')
		print()
		ucode_str = ", microcode 0x{:x}".format(sample['microcode']) if 'microcode' in sample else ""
		print("\t| Model: {} (family {}, model {}, stepping {}{})".format(
			sample['model'], sample['family'], sample['model_num'], sample['stepping'], ucode_str))

		socket_cpus = [c for cid in core_ids for c in topology[phys_id][cid]]
		socket_nodes = sorted({cpu_to_node[c] for c in socket_cpus if c in cpu_to_node})
		for nid in socket_nodes:
			ninfo = node_meminfo.get(nid)
			if ninfo:
				print("\t| NUMA node {}: {} present ({} spanned)".format(
					nid,
					val_to_units_string(ninfo['present'], 1024),
					val_to_units_string(ninfo['spanned'], 1024)))
			else:
				print("\t| NUMA node {}".format(nid))

		# display available cpu scaling frequencies, ala sys/devices/system/cpu/cpu$phys_id/cpufreq/scaling_available_frequencies
#		print "\t| CPU frequencies: $cpu_freqs\n";
#		my $govs = read_sysfs_file("$root_base/sys/devices/system/cpu/cpu$phys_id/cpufreq/scaling_available_governors");
#		my $current_gov = read_sysfs_file("$root_base/sys/devices/system/cpu/cpu$phys_id/cpufreq/scaling_governor");

#		print("\t| CPU scaling governors: {} (active: {})".format(govs, current_gov))
#or if not available:
#		print("\t| CPU frequency adjustment not available or not enabled")

		for core_id in core_ids:
			cpunums = topology[phys_id][core_id]
			cpunum = topology[phys_id][core_id]

			print("\t+->core {}: ".format(core_id), end='')

			thread_count = len(cpunums)
			if thread_count > 1:
				print("{} threads: ".format(thread_count), end='')
			cpu_strs = [ "cpu{}".format(cpu) for cpu in cpunums ]
			print("{}".format(", ".join(cpu_strs)), end='')

			print()
			if cpunums:
				print_cpu_cacheinfo(ci_addrs, cpunums[0], indent="\t     ")

if __name__ == "__main__":

	show_cpuinfo()

# vim: sw=4 ts=4 noexpandtab
