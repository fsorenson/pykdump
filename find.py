#!/usr/bin/python

import os, sys
from pykdump.API import *
from LinuxDump.fs.dcache import *


#if __name__ == "__main__":
#	mypath = os.path.dirname(os.path.realpath(sys.argv[0]))
#	check_paths = [mypath, "/root/crash"]
#	for p in check_paths:
#		if os.path.isdir(p):
#			if p not in sys.path:
#				sys.path.append(p)


#from fs_lib import *
maxel = 2000000
_MAXEL = maxel

INO_STATE_C = '''
#define DIRTY_SYNC 0
#define DIRTY_DATASYNC 1
#define DIRTY_PAGES 2
#define NEW 3
#define WILL_FREE 4
#define FREEING 5
#define CLEAR 6
#define LOCK 7
#define SYNC 8
'''
INO_STATE = CDefine(INO_STATE_C)

INO_FLAGS_C = '''
#define SYNC 0
#define NOATIME 1
#define APPEND 2
#define IMMUTABLE 3
#define DEAD 4
#define NOQUOTA 5
#define DIRSYNC 6
#define NOCMTIME 7
#define SWAPFILE 8
#define PRIVATE 9
#define AUTOMOUNT 11
#define AOP_EXT 14
'''
INO_FLAGS = CDefine(INO_FLAGS_C)

def inode_mode_type_char(mode):
	ret = '?'
	if (S_ISREG(mode)): ret = '-'
	elif (S_ISSOCK(mode)): ret = 's'
	elif (S_ISLNK(mode)): ret = 'l'
	elif (S_ISBLK(mode)): ret = 'b'
	elif (S_ISDIR(mode)): ret = 'd'
	elif (S_ISCHR(mode)): ret = 'c'
	elif (S_ISFIFO(mode)): ret = 'p'
	return ret

def inode_mode_type_string(mode):
	ret = '???'
	if (S_ISREG(mode)): ret = 'REG'
	elif (S_ISSOCK(mode)): ret = 'SOCK'
	elif (S_ISLNK(mode)): ret = 'LNK'
	elif (S_ISBLK(mode)): ret = 'BLK'
	elif (S_ISDIR(mode)): ret = 'DIR'
	elif (S_ISCHR(mode)): ret = 'CHR'
	elif (S_ISFIFO(mode)): ret = 'FIFO'
	return ret

__mbits = ['---', '--x', '-w-', '-wx', 'r--', 'r-x', 'rw-', 'rwx']

def mode_bits_string(mode):
	oth = list(__mbits[mode &  7])
	grp = list(__mbits[(mode >> 3) & 7])
	usr = list(__mbits[(mode >> 6) & 7])
	if (mode & S_ISUID):
		if (usr[2] == 'x'): usr[2] = 's'
		else: usr[2] = 'S'
	if (mode & S_ISGID):
		if (grp == 'x'): grp[2] = 's'
		else: grp[2] = 'S'
	if (mode & S_ISVTX):
		if (oth[2] == 'x'): oth[2] = 't'
		else: oth[2] = 'T'
	return "{}".format("".join(usr + grp + oth))
#"%s%s%s" % (
#			usr, grp, oth)
#s_t+''.join(p_u+p_g+p_o

def indent(lvl):
	return "{spaces}".format(spaces = ' ' * 4 * lvl)

def qstr(addr):
	try:
		q = readSU("struct qstr", long(addr))
		len = q.len
		if len:
			return readmem(q.name, q.len)
		return ""
	except:
		print("hmm. some exception")
		raise

# takes path, dentry, inode
def output_stat_info(path, dentry, inode):
	if dentry == 0: return

	if inode == 0:
		print("{:11s}  dentry: 0x{d:016x}, {p} (stale)".format("???????????", d=dentry, p=path))
		return

	i_mode = inode.i_mode
	itype = i_mode & S_IFMT
	obits = i_mode ^ itype
	mode_string = "{}{}".format(inode_mode_type_char(itype), mode_bits_string(obits))

	print("{ms:11s}  dentry: 0x{d:016x}, inode: 0x{i:016x}, {p}".format(ms=mode_string, d=dentry, i=inode, p=path))

	print("{ind}ino: {ino}, Size: {s:11d},  Blocks: {b},  Block size: {bs}    {typ}".format(ind=indent(1), ino=inode.i_ino, s=inode.i_size, b=inode.i_blocks, bs=(1 << inode.i_blkbits), typ=inode_mode_type_string(itype)))

	# could also output i_mode in {mode:o} format
	# atime, mtime, ctime



def find_recurse(path="/", addr=0):
	if addr == 0: return

	dentry = readSU("struct dentry", addr)
	d_subdirs_head = dentry.d_subdirs

	tmp_subdirs = readListByHead(d_subdirs_head, maxel=maxel)
	for tmp_entry in tmp_subdirs:
		try:
			dentry = readSU("struct dentry", container_of(tmp_entry, "struct dentry", "d_u"))
			inode = dentry.d_inode
		except:
			raise
			inode = 0
			pass

		path_ele = qstr(dentry.d_name)
		new_path = path + "/" + str(path_ele, 'utf-8')
		output_stat_info(new_path, dentry, inode)

		if inode:
			i_mode = inode.i_mode
			itype = i_mode & S_IFMT

			if S_ISDIR(inode.i_mode):
				find_recurse(new_path, dentry)

def get_arg_value(arg):
	try:
		if arg.lower().startswith('0x'):
			return int(arg, 16)
		if arg.startswith('0') and all(c in string.octdigits for c in arg):
			return int(arg, 8)
#	if all(c in string.intdigits for c in arg): ### stupid python doesn't have string.intdigits?
		if all(c in '0123456789' for c in arg):
			return int(arg, 10)
		return int(arg, 16)
	except ValueError:
		return 0


def foreach_argv_dentry_find():
	for arg in sys.argv:
		addr = get_arg_value(arg)
		if addr != 0:
			find_recurse("0x{:016x}".format(addr), addr)

if __name__ == "__main__":
	foreach_argv_dentry_find()

# vim: sw=4 ts=4 noexpandtab
