#!/usr/bin/python

import os, sys
from pykdump.API import *

def get_arg_value(arg):
	try:
		if arg.lower().startswith('0x'):
			return int(arg, 16)
		if arg.startswith('0') and all(c in string.octdigits for c in arg):
			return int(arg, 8)
		if all(c in '0123456789' for c in arg):
			return int(arg, 10)
		return int(arg, 16)
	except ValueError:
		return 0



DCACHE_C = '''
#define DCACHE_ENTRY_TYPE               0x00700000
#define DCACHE_MISS_TYPE                0x00000000 /* Negative dentry (maybe fallthru to nowhere) */
#define DCACHE_WHITEOUT_TYPE            0x00100000 /* Whiteout dentry (stop pathwalk) */
#define DCACHE_DIRECTORY_TYPE           0x00200000 /* Normal directory */
#define DCACHE_AUTODIR_TYPE             0x00300000 /* Lookupless directory (presumed automount) */
#define DCACHE_REGULAR_TYPE             0x00400000 /* Regular file type (or fallthru to such) */
#define DCACHE_SPECIAL_TYPE             0x00500000 /* Other file type (or fallthru to such) */
#define DCACHE_SYMLINK_TYPE             0x00600000 /* Symlink (or fallthru to such) */
'''
DCACHE = CDefine(DCACHE_C)


def __d_entry_type(dentry):
	return dentry.d_flags & DCACHE['DCACHE_ENTRY_TYPE']


def d_is_miss(dentry):
	__d_entry_type(dentry) == DCACHE['DCACHE_MISS_TYPE']

def d_cache_type(dentry):
	typ = dentry.d_flags & DCACHE['DCACHE_ENTRY_TYPE']
	if not typ: return "miss"
	if typ == DCACHE['DCACHE_WHITEOUT_TYPE']: return "whiteout"
	if typ == DCACHE['DCACHE_DIRECTORY_TYPE']: return "directory"
	if typ == DCACHE['DCACHE_AUTODIR_TYPE']: return "autodir"
	if typ == DCACHE['DCACHE_REGULAR_TYPE']: return "file"
	if typ == DCACHE['DCACHE_SPECIAL_TYPE']: return "other"
	if typ == DCACHE['DCACHE_SYMLINK_TYPE']: return "symlink"
	return "unknown"

def is_negative(dentry):
	return d_is_miss(dentry)

def cleanup_str(s):
	new_str = ""
	for a in s:
		if (a.isprintable()) == False:
			return new_str
	else:
		new_str += a
	return new_str

def qstr(addr):
	try:
		q = readSU("struct qstr", long(addr))
		if q.len:
			return readmem(q.name, q.len)
		return ""
	except:
		pass
	return ""

def get_dentry_name(dentry):
	name_ptr = readPtr(Addr(dentry.d_name, extra='name'))

	if name_ptr == Addr(dentry, extra='d_iname'):
		path_ele = qstr(dentry.d_name)
		try:
			return cleanup_str(str(path_ele, 'utf-8'))
		except:
			return "???"
	try:
		path_ele = qstr(dentry.d_name, complain)
		return cleanup_str(str(path_ele, 'utf-8'))
	except:
		pass
	return "name freed"


def print_one_dentry(dentry):
#	dentry_name = get_dentry_name(dentry)
	dentry_name = get_pathname(dentry, 0)

	print("0x{:016x} {} - {}".format(dentry, d_cache_type(dentry), dentry_name))
#	if is_negative(dentry):
#		print("0x{:016x} negative - {}".format(dentry, dentry_name))
#	else:
#		print("0x{:016x} positive - {}".format(dentry, dentry_name))

def process_start(addr):
	if addr == 0: return

	dentry = readSU("struct dentry", addr)
	print_one_dentry(dentry)

	if not is_negative(dentry):
		try:
			d_subdirs_head = int(dentry.d_subdirs)
			if d_subdirs_head == 0: return
		except Exception as e:
			exc_info = sys.exc_info()
			print("error reading subdirs head in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
			traceback.print_tb(sys.exc_info()[2])
			sys.exit()
		nxt = d_subdirs_head

		while 42:
			try:
				nxt = readPtr(nxt)
			except crash.error as e:
				print("error: {}".format(e))
				print(e)
				break
			if (nxt == 0) or (nxt == d_subdirs_head):
				break
			try:
#				dentry = readSU("struct dentry", nxt + subdirs_offset)
				dentry = readSU("struct dentry", container_of(nxt, "struct dentry", "d_child"))
			except Exception as e:
				print("error in find_recurse: {}".format(e))
				raise
			print_one_dentry(dentry)


if __name__ == "__main__":
	subdirs_offset = container_of(0, "struct dentry", "d_subdirs")
	for addr_str in sys.argv[1:]:
		addr = get_arg_value(addr_str)
		process_start(addr)

# vim: sw=4 ts=4 noexpandtab
