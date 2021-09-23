#!/usr/bin/python

import os, sys
from pykdump.API import *
from LinuxDump.fs.dcache import *
import argparse

__author__ = "Frank Sorenson <sorenson@redhat.com>"
__version__ = "1.1.0"

maxel = 2000000
_MAXEL = maxel
verbosity = 0
DEBUG = 0
maxdepth = 0
recurse = True
show_stale = True

def rhel_major_version():
	if sys_info.kernel >= "4.18.0" and sys_info.kernel <= "4.18.0":
		return 8
	if sys_info.kernel >= "3.10.0" and sys_info.kernel <= "3.10.0":
		return 7
	if sys_info.kernel >= "2.6.32" and sys_info.kernel <= "2.6.32":
		return 6
	if sys_info.kernel >= "2.6.18" and sys_info.kernel <= "2.6.18":
		return 5

RHEL_VERSION_STRS_el = [ 'el5', 'el6', 'el7', 'el8' ]
def is_rhel():
	for s in RHEL_VERSION_STRS_el:
		if s in sys_info.RELEASE:
			return 1
	return 0

# from include/linux/dcache.c d_flags entries
DFLAGS_C = '''
#define DCACHE_OP_HASH          0x0001
#define DCACHE_OP_COMPARE       0x0002
#define DCACHE_OP_REVALIDATE    0x0004
#define DCACHE_OP_DELETE        0x0008
#define DCACHE_OP_PRUNE         0x0010

#define DCACHE_DISCONNECTED     0x0020
#define DCACHE_REFERENCED       0x0040  /* Recently used, don't discard. */
#define DCACHE_RCUACCESS        0x0080  /* Entry has ever been RCU-visible */

#define DCACHE_CANT_MOUNT       0x0100
#define DCACHE_GENOCIDE         0x0200
#define DCACHE_SHRINK_LIST      0x0400

#define DCACHE_OP_WEAK_REVALIDATE       0x0800

#define DCACHE_NFSFS_RENAMED    0x1000
#define DCACHE_COOKIE           0x2000  /* For use by dcookie subsystem */
#define DCACHE_FSNOTIFY_PARENT_WATCHED 0x4000

#define DCACHE_MOUNTED          0x10000 /* is a mountpoint */
#define DCACHE_NEED_AUTOMOUNT   0x20000 /* handle automount on this dir */
#define DCACHE_MANAGE_TRANSIT   0x40000 /* manage transit from this dirent */

#define DCACHE_LRU_LIST         0x80000
#define DCACHE_DENTRY_KILLED    0x100000

#define DCACHE_ENTRY_TYPE               0x07000000
#define DCACHE_MISS_TYPE                0x00000000 /* Negative dentry */
#define DCACHE_DIRECTORY_TYPE           0x01000000 /* Normal directory */
#define DCACHE_AUTODIR_TYPE             0x02000000 /* Lookupless directory (presumed automount) */
#define DCACHE_SYMLINK_TYPE             0x03000000 /* Symlink */
#define DCACHE_FILE_TYPE                0x04000000 /* Other file type */
#define DCACHE_OP_REAL                  0x08000000
'''
DFLAGS_C_RHEL6 = '''
#define DCACHE_AUTOFS_PENDING 0x0001    /* autofs: "under construction" */
#define DCACHE_NFSFS_RENAMED  0x0002
#define DCACHE_DISCONNECTED 0x0004
#define DCACHE_REFERENCED       0x0008  /* Recently used, don't discard. */
#define DCACHE_UNHASHED         0x0010

#define DCACHE_INOTIFY_PARENT_WATCHED 0x0020
#define DCACHE_COOKIE           0x0040  /* For use by dcookie subsystem */

#define DCACHE_FSNOTIFY_PARENT_WATCHED 0x0080
     /* Parent inode is watched by some fsnotify listener */

#define DCACHE_MOUNTED          0x10000 /* is a mountpoint */
#define DCACHE_NEED_AUTOMOUNT   0x20000 /* handle automount on this dir */
#define DCACHE_MANAGE_TRANSIT   0x40000 /* manage transit from this dirent */
#define DCACHE_MANAGED_DENTRY \
        (DCACHE_MOUNTED|DCACHE_NEED_AUTOMOUNT|DCACHE_MANAGE_TRANSIT)

#define DCACHE_SHRINKING        0x80000000 /* dentry is being shrunk */
'''

# from include/linux/fs.h inode state bits
INO_STATE_C = '''
#define DIRTY_SYNC 0
#define DIRTY_DATASYNC 1
#define DIRTY_PAGES 2
#define NEW 3
#define WILL_FREE 4
#define FREEING 5
#define CLEAR 6
#define SYNC 7
#define REFERENCED 8
#define DIO_WAKEUP 9
#define LINKABLE 10
#define DIRTY_TIME 11
#define DIRTY_TIME_EXPIRED 12
#define WB_SWITCH 13
#define OVL_INUSE 14
#define CREATING 15
'''
INO_STATE = CDefine(INO_STATE_C)

# from include/linux/fs.h inode flags S_*
INO_FLAGS_C = '''
#define S_SYNC          1       /* Writes are synced at once */
#define S_NOATIME       2       /* Do not update access times */
#define S_APPEND        4       /* Append-only file */
#define S_IMMUTABLE     8       /* Immutable file */
#define S_DEAD          16      /* removed, but still open directory */
#define S_NOQUOTA       32      /* Inode is not counted to quota */
#define S_DIRSYNC       64      /* Directory modifications are synchronous */
#define S_NOCMTIME      128     /* Do not update file c/mtime */
#define S_SWAPFILE      256     /* Do not truncate: swapon got its bmaps */
#define S_PRIVATE       512     /* Inode is fs-internal */
#define S_AUTOMOUNT     2048    /* Automount/referral quasi-directory */
'''

if is_rhel() and rhel_major_version() == 6:
	DFLAGS_C = DFLAGS_C_RHEL6


# check for rhel 7 kernel, add flags
if is_rhel() and rhel_major_version() == 7:
	INO_FLAGS_C = INO_FLAGS_C + '''
#define S_IMA           1024    /* Inode has an associated IMA struct */
#define S_NOSEC         4096    /* no suid or xattr security attributes */
#define S_IOPS_WRAPPER  8192    /* i_op points to struct inode_operations_wrapper */
'''
	# if some common dax-related function exists, add S_DAX
	if symbol_exists('dax_do_io'):
		INO_FLAGS_C = INO_FLAGS_C + '''
#define S_DAX           16384   /* Direct Access, avoiding the page cache */
'''

# check for rhel 8 kernel, add flags
if is_rhel() and rhel_major_version() == 8:
	INO_FLAGS_C = INO_FLAGS_C + '''
#define S_IMA           1024    /* Inode has an associated IMA struct */
#define S_NOSEC         4096    /* no suid or xattr security attributes */
#define S_ENCRYPTED     16384   /* Encrypted file (using fs/crypto/) */
'''
	# if some common dax-related function exists, add S_DAX
	if symbol_exists('dax_do_io'):
		INO_FLAGS_C = INO_FLAGS_C + '''
#define S_DAX           8192   /* Direct Access, avoiding the page cache */
'''

DFLAGS = CDefine(DFLAGS_C)
INO_FLAGS = CDefine(INO_FLAGS_C)

#print("ino_flags_c: {}".format(INO_FLAGS_C))
#print("INO_FLAGS: {}".format(INO_FLAGS))


def pp_time_ns(ns):
	ret = ""
	s = int(ns / 1000000000)
	ns %= 1000000000
	m = int(s / 60)
	s %= 60
	h = int(m / 60)
	m %= 60
	d = int(h / 24)
	h %= 24
	if d:
		ret = "{} day{} ".format(d, "s" if d > 1 else "")

	ret = "{}{:2d}:{:02d}:{:02d}.{:09d}".format(ret, h, m, s, ns)
	return ret

def pp_time_us(us):
	return pp_time_ns(us * 1000)[:-3]

def pp_time_ms(ms):
	return pp_time_ns(ms * 1000 * 1000)[:-6]

def pp_time_s(s):
	return pp_time_ns(s * 1000 * 1000 * 1000)[:-10]

def timespec_to_string(ts_in):
	try:
		ts_in = readSU("struct timespec", ts_in)

		import time
		lt = time.localtime(ts_in.tv_sec)
		return "{s}.{ns:09d} {tz}".format(s = time.strftime('%Y-%m-%d %H:%M:%S', lt),
			ns = ts_in.tv_nsec, tz = time.strftime('%Z', lt))
	except:
		return ""

def flag_bits_to_string(flags, strings):
	result = []
	for name, val in strings.items():
#		print("testing '{}' - 0x{:x} & 0x{:x}".format(name, 1 << val, flags))
		if flags & (1 << val) != 0:
			result.append(name)
			flags = flags & ~(1 << val)
	if flags:
		result.append("0x{:08x}".format(flags))
	return "|".join(result)

def flags_to_string(flags, strings):
	result = []
	for name, val in strings.items():
#		print("testing '{}' - 0x{:x} & 0x{:x}".format(name, val, flags))
		if flags & val == val:
			result.append(name)
			flags = flags & ~val
	if flags:
		result.append("0x{:08x}".format(flags))
	return "|".join(result)


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
		print("{:11s}  dentry: 0x{:016x}, {} (stale)".format(
			"???????????", dentry, path))
	else:
		try:
			i_mode = inode.i_mode
			itype = i_mode & S_IFMT
			obits = i_mode ^ itype
			mode_string = "{}{}".format(inode_mode_type_char(itype), mode_bits_string(obits))
			mode_type_string = inode_mode_type_string(itype)
		except:
			mode_string = "???????????"
			mode_type_string = "UNKNOWN"

		print("{:11s}  dentry: 0x{:016x}, inode: 0x{:016x}, {}".format(
			mode_string, dentry, inode, path))

	if verbose:
		print("{}.d_flags: 0x{:08x} - {}".format(indent(2), dentry.d_flags, flags_to_string(dentry.d_flags, DFLAGS)))

	if inode == 0:
		return

	try:
		ino = inode.i_ino
		size = inode.i_size
		blocks = inode.i_blocks
		bs = (1 << inode.i_blkbits)
	except:
		ino = "?"
		size = -1
		blocks = "?"
		bs = "?"
		mode_type_string = "?"

	print("{ind}ino: {ino}, Size: {s:11d},  Blocks: {b},  Block size: {bs}    {typ}".format(ind=indent(1),
		ino=ino, s=size, b=blocks, bs=bs, typ=mode_type_string))
#		ino=inode.i_ino, s=inode.i_size, b=inode.i_blocks, bs=(1 << inode.i_blkbits), typ=inode_mode_type_string(itype)))

	try:
		uid = inode.i_uid
		gid = inode.i_gid
		try:
			uid = uid.val
			gid = gid.val
		except:
			pass
	except:
		uid = "?"
		gid = "?"

	# could also output i_mode in {mode:o} format
	if verbose:
		print("{}uid: {}, gid: {}, links: {}".format(indent(2), uid, gid, inode.i_nlink))

		i_state_str = flag_bits_to_string(inode.i_state, INO_STATE)
		i_flags_str = flags_to_string(inode.i_flags, INO_FLAGS)

		print("{}.i_state: 0x{:08x} - {}".format(indent(2), inode.i_state, i_state_str))
		print("{}.i_flags: 0x{:08x} - {}".format(indent(2), inode.i_flags, i_flags_str))

		print("{}atime: {}".format(indent(2), timespec_to_string(inode.i_atime)))
		print("{}mtime: {}".format(indent(2), timespec_to_string(inode.i_mtime)))
		print("{}ctime: {}".format(indent(2), timespec_to_string(inode.i_ctime)))

def cleanup_str(str):
	new_str = ""
	for a in str:
		if (a.isprintable()) == False:
			return new_str
		else:
			new_str += a
	return new_str

def get_dentry_name(dentry):
	# was the filename embedded?  can we use the name?
	name_ptr = readPtr(Addr(dentry.d_name, extra='name'))

	if name_ptr == Addr(dentry, extra='d_iname'):
#	if readPtr(Addr(dentry.d_name, extra='name')) == Addr(dentry, extra='d_iname'):
		path_ele = qstr(dentry.d_name)
		try:
			return cleanup_str(str(path_ele, 'utf-8'))
		except:
			return "????? - cannot read 0x{:016x}".format(dentry.d_name)
	try:
#		name = readPtr(Addr(dentry.d_name, extra='name'))
		path_ele = qstr(dentry.d_name)
		return cleanup_str(str(path_ele, 'utf-8'))
	except:
		pass
	return "<name freed>"



def find_recurse(path="/", addr=0, depth=1):
	if addr == 0: return
	if maxdepth > 0 and depth > maxdepth:
		return


	dentry = readSU("struct dentry", addr)

#	output_stat_info(path, dentry, dentry.d_inode)

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

		# was the filename embedded?  can we use the name?
		dentry_name = get_dentry_name(dentry)
		if len(dentry_name) == 0:
			continue

#		print("{}-byte string '{}' is printable, apparently".format(len(dentry_name), dentry_name));
		new_path = path + "/" + dentry_name
		output_stat_info(new_path, dentry, inode)

		if inode:
			try:
				i_mode = inode.i_mode
				i_type = i_mode & S_IFMT

				if S_ISDIR(i_mode):
					find_recurse(new_path, dentry, depth=depth+1)
			except:
				pass

def find_recurse_begin(path="/", addr=0):
	if addr == 0: return

	dentry = readSU("struct dentry", addr)
	dentry_name = get_dentry_name(dentry)

	path = "0x{:016x} ({})".format(dentry, dentry_name)

	output_stat_info(path, dentry, dentry.d_inode)
	if recurse:
		find_recurse(path, dentry)


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


if __name__ == "__main__":
	opts_parser = argparse.ArgumentParser()
	opts_parser.add_argument('--verbose', '-v', dest = 'verbose', default = 0, action = 'count', help = "increase verbosity")
	opts_parser.add_argument("--maxdepth", dest = 'maxdepth', type=int, default = -1, help = "set a maximum subdirectory depth")
	opts_parser.add_argument("--nostale", dest = 'nostale', default = False, action = "store_true", help = "suppress display of stale entries")
	opts_parser.add_argument("--norecurse", '-d', dest = 'norecurse', default = False, action = "store_true", help = "only show info for listed dentries")

	addrs_parser = argparse.ArgumentParser()
	addrs_parser.add_argument('addrs', action = 'store', nargs = '*')

	opts, remain = opts_parser.parse_known_args(sys.argv[1:])
	opts = addrs_parser.parse_args(remain, opts)

	verbose = opts.verbose
	maxdepth = opts.maxdepth
	show_stale = not(opts.nostale)
	if opts.norecurse:
		recurse = False

	for addr_str in opts.addrs:
		try:

			addr = get_arg_value(addr_str)
			if addr:
				find_recurse_begin("0x{:016x}".format(addr), addr)
		except Exception as e:
			print("error: {}".format(e))

# vim: sw=4 ts=4 noexpandtab
