#!/usr/bin/python

import sys, os

if __name__ == "__main__":
	mypath = os.path.dirname(os.path.realpath(sys.argv[0]))
	if mypath not in sys.path:
		sys.path.append(mypath)

from sorenson_lib import *
from pykdump.API import *

from LinuxDump.fs.dcache import *
from LinuxDump.idr import idr_for_each

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
	if not gen:
		return
	display_generic_struct_member(gen, "disk_name", ilvl=ilvl)
	part0 = gen.part0
	if part0:
		if part0.hasField("bd_nr_sectors"):
			nr_sects = part0.bd_nr_sectors
		elif part0.hasField("nr_sects"):
			nr_sects = part0.nr_sects
		else:
			nr_sects = None
		if nr_sects is not None:
			print("{}size: {}".format(indent_str(ilvl), nr_sects * 512))


def display_block_device(bdev, ilvl=0, rlvl=0):
	if not bdev:
		return
	display_generic_struct_member(bdev, "bd_inode", rlvl=rlvl, ilvl=ilvl)
	display_generic_struct_member(bdev, "bd_mapping", rlvl=rlvl, ilvl=ilvl)
	display_generic_struct_member(bdev, "bd_super", rlvl=rlvl, ilvl=ilvl)

	display_generic_struct_member(bdev, "bd_disk", rlvl=rlvl, ilvl=ilvl)
	if bdev.bd_disk:
		display_gendisk(bdev.bd_disk, ilvl=ilvl+1)

	display_generic_struct_member(bdev, "bd_queue", rlvl=rlvl, ilvl=ilvl)
	display_generic_struct_member(bdev, "bd_mutex", rlvl=rlvl, ilvl=ilvl)
	display_generic_struct_member(bdev, "bd_block_size", rlvl=rlvl, ilvl=ilvl)


def do_display_loop_dev(num, addr):
	ldev = readSU("struct loop_device", addr)

	ilvl = 1

	print("{}) (struct loop_device *)0x{:016x} - loop{}".format(num, ldev, ldev.lo_number))

	print("{}.lo_number = {}, .lo_file_name = {}".format(indent_str(ilvl), ldev.lo_number, ldev.lo_file_name))
	lo_blocksize = ldev.lo_blocksize if ldev.hasField("lo_blocksize") else "?"
	print("{}.lo_offset = {}, .lo_sizelimit = {}, .lo_blocksize = {}".format(indent_str(ilvl), ldev.lo_offset, ldev.lo_sizelimit, lo_blocksize))

	if ldev.hasField("lo_thread") and ldev.lo_thread:
		thread = ldev.lo_thread
		print("{}.lo_thread = {} ({})".format(indent_str(ilvl), thread, thread.comm))

	filp = ldev.lo_backing_file
	print("{}.lo_backing_file = {}".format(indent_str(ilvl), filp))
	if filp:
		dentry = file_get_dentry(filp)
		vfsmnt = file_get_vfsmnt(filp)
		pathname = get_pathname(dentry, vfsmnt)
		print("{}(struct dentry *)0x{:016x} ({})".format(indent_str(ilvl+1), dentry, pathname))

	print("{}.lo_device = {}".format(indent_str(ilvl), ldev.lo_device))
	if ldev.lo_device:
		display_block_device(ldev.lo_device, ilvl=ilvl+1)
	print("{}.lo_disk = {}".format(indent_str(ilvl), ldev.lo_disk))


def do_display_loop_devs():
	if not symbol_exists("loop_index_idr"):
		print("loop_index_idr symbol not found")
		return

	loop_index_idr = readSymbol("loop_index_idr")
	found = 0
	for _id, val in idr_for_each(loop_index_idr):
		if not val:
			continue
		found += 1
		do_display_loop_dev(_id, val)
	if not found:
		print("No loop devices found")




if __name__ == "__main__":
#	addr = get_arg_value(argv[x])
	do_display_loop_devs()

# vim: sw=4 ts=4 noexpandtab
