#!/usr/bin/python

from __future__ import print_function

import sys, os

if __name__ == "__main__":
	mypath = os.path.dirname(os.path.realpath(sys.argv[0]))
	if mypath not in sys.path:
		sys.path.append(mypath)

from fs_lib import *
from file import *
from pykdump.API import *
#from misc.percpu import get_per_cpu


from LinuxDump.Tasks import TaskTable
from LinuxDump.fs.dcache import *
from LinuxDump.trees import *
from LinuxDump.idr import *


def ffs(x):
	"""Returns the index, counting from 1, of the
	least significant set bit in `x`.
	"""
	return (x&-x).bit_length()



# On newer kernels:
#define RADIX_TREE_INDEX_BITS  (8 /* CHAR_BIT */ * sizeof(unsigned long))
#define RADIX_TREE_MAX_PATH (DIV_ROUND_UP(RADIX_TREE_INDEX_BITS, \
#                                          RADIX_TREE_MAP_SHIFT))

#/* Height component in node->path */
#define RADIX_TREE_HEIGHT_SHIFT (RADIX_TREE_MAX_PATH + 1)
#define RADIX_TREE_HEIGHT_MASK  ((1UL << RADIX_TREE_HEIGHT_SHIFT) - 1)
# static unsigned long height_to_maxindex[RADIX_TREE_MAX_PATH + 1]
RADIX_TREE_MAP_SIZE = None
RADIX_TREE_HEIGHT_MASK = None

_rnode = "struct radix_tree_node"
try:
	ti = getStructInfo(_rnode)["slots"].ti
	RADIX_TREE_MAP_SIZE = ti.dims[0]
	RADIX_TREE_MAP_MASK = RADIX_TREE_MAP_SIZE - 1
	RADIX_TREE_MAP_SHIFT = ffs(RADIX_TREE_MAP_SIZE) - 1
	RADIX_TREE_INDIRECT_PTR = 1
	height_to_maxindex = readSymbol("height_to_maxindex")
	# Are we on a kernel with 'radix_tree_node.path'?
	if (member_size(_rnode, "path") != -1):
            # Yes, we are
			RADIX_TREE_MAX_PATH = len(height_to_maxindex)-1
			RADIX_TREE_HEIGHT_SHIFT = RADIX_TREE_MAX_PATH + 1
			RADIX_TREE_HEIGHT_MASK = (1 << RADIX_TREE_HEIGHT_SHIFT) - 1
except:
	pass



def indirect_to_ptr(ptr):
#return (void *)((unsigned long)ptr & ~RADIX_TREE_INDIRECT_PTR);
	return (long(ptr) & ~RADIX_TREE_INDIRECT_PTR)


def radix_tree_nodes_orig(ptree):
	first_rnode = readSU("struct radix_tree_node", indirect_to_ptr(ptree.rnode))
	if (not first_rnode):
		return []
	pheight = ptree.height
	_offset = member_offset("struct radix_tree_node", "slots")
	_size = RADIX_TREE_MAP_SIZE * pointersize

	def walk_radix_node(rnode, height):
		arr = mem2long(readmem(rnode+_offset, _size), array=RADIX_TREE_MAP_SIZE)
		for i, s in enumerate(arr):
			if (not s):
				continue
			if (height == 1):
				yield s
			else:
				for s1 in walk_radix_node(s, height-1):
					yield s1
	return walk_radix_node(long(first_rnode), pheight)

def radix_tree_nodes(ptree):
	ptree = readSU("struct radix_tree_node", ptree)
	def get_nodes(addr):
		for l in exec_crash_command("tree -t ra 0x{:016x}".format(addr)).split("\n"):
			if l != '':
				a = get_arg_value(l)
				yield a
	nodes = get_nodes(ptree)
	return nodes

#struct block_device {
#    dev_t bd_dev;
#    int bd_openers;
#    struct inode *bd_inode;
#    struct super_block *bd_super;
#    struct mutex bd_mutex;
#    struct list_head bd_inodes;
#    void *bd_claiming;
#    void *bd_holder;
#    int bd_holders;
#    bool bd_write_holder;
#    struct list_head bd_holder_disks;
#    struct block_device *bd_contains;
#    unsigned int bd_block_size;
#    struct hd_struct *bd_part;
#    unsigned int bd_part_count;
#    int bd_invalidated;
#    struct gendisk *bd_disk;
#    struct request_queue *bd_queue;
#    struct list_head bd_list;
#    unsigned long bd_private;
#    int bd_fsfreeze_count;
#    struct mutex bd_fsfreeze_mutex;

#def display_super_block(sb):


def struct__member_obj(struct_obj, member):
	try:
		if struct_obj.hasField(member):
			member_obj = struct_obj.Eval(member)
			return member_obj
	except:
		pass
	return None

def display_generic_struct_member(addr, member_name, rlvl=0, ilvl=0):
	member_obj = struct__member_obj(addr, member_name)
	if member_obj == None:
		return

	try:
		sym = member_obj.PYT_symbol
		if sym.startswith('struct '):
#			member_type = sym[7:]
			print("{}.{} - ({} *)0x{:016x}".format(indent_str(ilvl), member_name, sym, long(member_obj)))
			return
	except AttributeError:
		pass

	if type(member_obj) == type(0):
		print("{}.{} - {}".format(indent_str(ilvl), member_name, member_obj))
	elif isinstance(member_obj, SmartString):
		print("{}.{} - (char *){} - '{}'".format(indent_str(ilvl), member_name, member_obj.addr, member_obj))
	else:
		print("{}.{} - (unknown type: {}) 0x{:016x}".format(indent_str(ilvl), member_name, member_obj, long(member_obj)))

def display_gendisk(gen, ilvl=0, rlvl=0):
	display_generic_struct_member(gen, "disk_name", ilvl=ilvl)
	part0 = gen.part0
	print("{}size: {}".format(indent_str(ilvl), part0.nr_sects*512))


def display_block_device(bdev, ilvl=0, rlvl=0):
	display_generic_struct_member(bdev, "bd_inode", rlvl=rlvl, ilvl=ilvl)
	display_generic_struct_member(bdev, "bd_super", rlvl=rlvl, ilvl=ilvl)

	display_generic_struct_member(bdev, "bd_disk", rlvl=rlvl, ilvl=ilvl)
	display_gendisk(bdev.bd_disk, ilvl=ilvl+1)

	display_generic_struct_member(bdev, "bd_queue", rlvl=rlvl, ilvl=ilvl)
	display_generic_struct_member(bdev, "bd_mutex", rlvl=rlvl, ilvl=ilvl)

#	print("{}.bd_inode: (struct inode *)0x{:016x}".format(indent_str(ilvl), bdev.bd_inode))
#	print("{}.bd_super: (struct super_block *)0x{:016x}".format(indent_str(ilvl), bdev.bd_super))
#	print(indent_str(ilvl), ".bd_block_size = {}".format(bdev.bd_block_size))
	display_generic_struct_member(bdev, "bd_block_size", rlvl=rlvl, ilvl=ilvl)


def do_display_loop_dev(num, addr):
	ldev = readSU("struct loop_device", addr)

	ilvl=1

	print("{}) (struct loop_device *)0x{:016x} - loop{}".format(num, ldev, ldev.lo_number))

	print("{}.lo_number = {}, .lo_file_name = {}".format(indent_str(ilvl), ldev.lo_number, ldev.lo_file_name))
	try:
		lo_blocksize = ldev.lo_blocksize
	except:
		lo_blocksize = "?"
		pass
	print("{}.lo_offset = {}, .lo_sizelimit = {}, .lo_blocksize = {}".format(indent_str(ilvl), ldev.lo_offset, ldev.lo_sizelimit, lo_blocksize))

	try:
		thread = ldev.lo_thread
		comm = thread.comm
		print("{}.lo_thread = {} ({})".format(indent_str(ilvl), thread, comm))
	except:
		pass # oh shaddap

	filp = ldev.lo_backing_file
	dentry = file_get_dentry(filp)
	vfsmnt = file_get_vfsmnt(filp)
	pathname = get_pathname(dentry, vfsmnt)

	print("{}.lo_backing_file = {}".format(indent_str(ilvl), filp))
	print("{}(struct dentry *)0x{:016x} ({})".format(indent_str(ilvl+1), dentry, pathname))
	print("{}.lo_device = {}".format(indent_str(ilvl), ldev.lo_device))
	display_block_device(ldev.lo_device, ilvl=ilvl+1)
	print("{}.lo_disk = {}".format(indent_str(ilvl), ldev.lo_disk))



def do_display_loop_devs():
	try:
		loop_index_idr = readSymbol("loop_index_idr")
	except:
		return


	try:
		# loop_index_idr is 'struct idr *'
		try:
			if (loop_index_idr.layers > 1):
				print("Hmm.  may have a problem...  not sure I can handle {} idr layers".format(loop_index_idr.layers))

			top = loop_index_idr.top # struct idr_layer

			bitmap = top.bitmap # unsigned long bitmap[4]
			for i in range(0, 3):
				bits = bitmap[i]
				for bit in range(0, 63):
					val = bits & (1 << bit)
					if val:
						index = (i * 64) + bit
						ldev = readSU("struct loop_device", top.ary[index])
#					print("{}.{} - {} is set: 0x{:016x}".format(i, bit, index, ldev))
						print("{}.{} - {} is set: 0x{:016x}".format(i, bit, index, ldev))
#				pp_struct("loop_device", ldev, rlvl=1, ilvl=1)
						do_display_loop_dev(index, ldev)
		except:
			devs = radix_tree_nodes(loop_index_idr.idr_rt)
			for d in devs:
				do_display_loop_dev(0, d)
	except:
		print("exception, trying alternate")
		for _id, val in idr_for_each(loop_index_idr):
			if _id != 0:
				continue
			print("idr {}: 0x{:016x}".format(_id, val))
			do_display_loop_dev(_id, val)




if __name__ == "__main__":
#	addr = get_arg_value(argv[x])
	do_display_loop_devs()

# vim: sw=4 ts=4 noexpandtab
