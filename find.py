#!/usr/bin/python

import os, sys
from pykdump.API import *
from LinuxDump.fs.dcache import *
from LinuxDump.Tasks import (TaskTable, Task)
import argparse
import inspect

__author__ = "Frank Sorenson <sorenson@redhat.com>"
__version__ = "1.1.0"

maxel = 2000000
_MAXEL = maxel
verbosity = 0
DEBUG = 0
maxdepth = 0
recurse = True
show_stale = True

#define KERNFS_TYPE_MASK        0x000f
KERNFS_TYPE_MASK = 0x000f
KERNFS_DIR = enumerator_value("KERNFS_DIR")
KERNFS_FILE = enumerator_value("KERNFS_FILE")
KERNFS_LINK = enumerator_value("KERNFS_LINK")


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

DFLAGS_C_RHEL8 = '''
#define DCACHE_OP_HASH                  0x00000001
#define DCACHE_OP_COMPARE               0x00000002
#define DCACHE_OP_REVALIDATE            0x00000004
#define DCACHE_OP_DELETE                0x00000008
#define DCACHE_OP_PRUNE                 0x00000010

#define DCACHE_DISCONNECTED             0x00000020
#define DCACHE_REFERENCED               0x00000040 /* Recently used, don't discard. */

#define DCACHE_CANT_MOUNT               0x00000100
#define DCACHE_GENOCIDE                 0x00000200
#define DCACHE_SHRINK_LIST              0x00000400

#define DCACHE_OP_WEAK_REVALIDATE       0x00000800
#define DCACHE_NFSFS_RENAMED            0x00001000
#define DCACHE_COOKIE                   0x00002000 /* For use by dcookie subsystem */
#define DCACHE_FSNOTIFY_PARENT_WATCHED  0x00004000

#define DCACHE_DENTRY_KILLED            0x00008000

#define DCACHE_MOUNTED                  0x00010000 /* is a mountpoint */
#define DCACHE_NEED_AUTOMOUNT           0x00020000 /* handle automount on this dir */
#define DCACHE_MANAGE_TRANSIT           0x00040000 /* manage transit from this dirent */

#define DCACHE_LRU_LIST                 0x00080000

#define DCACHE_ENTRY_TYPE               0x00700000
#define DCACHE_MISS_TYPE                0x00000000 /* Negative dentry (maybe fallthru to nowhere) */
#define DCACHE_WHITEOUT_TYPE            0x00100000 /* Whiteout dentry (stop pathwalk) */
#define DCACHE_DIRECTORY_TYPE           0x00200000 /* Normal directory */
#define DCACHE_AUTODIR_TYPE             0x00300000 /* Lookupless directory (presumed automount) */
#define DCACHE_REGULAR_TYPE             0x00400000 /* Regular file type (or fallthru to such) */
#define DCACHE_SPECIAL_TYPE             0x00500000 /* Other file type (or fallthru to such) */
#define DCACHE_SYMLINK_TYPE             0x00600000 /* Symlink (or fallthru to such) */

#define DCACHE_MAY_FREE                 0x00800000
#define DCACHE_FALLTHRU                 0x01000000 /* Fall through to lower layer */
#define DCACHE_ENCRYPTED_WITH_KEY       0x02000000 /* dir is encrypted with a valid key */
#define DCACHE_OP_REAL                  0x04000000
#define DCACHE_DONTCACHE                0x08000000 /* Purge from memory on final dput() */

#define DCACHE_PAR_LOOKUP               0x10000000 /* being looked up (with parent locked shared) */
#define DCACHE_DENTRY_CURSOR            0x20000000
#define DCACHE_NORCU                    0x40000000 /* No RCU delay for freeing */
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
if is_rhel() and rhel_major_version() == 8:
	DFLAGS_C = DFLAGS_C_RHEL8


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

XFS_IFINLINE = 0x01
def readlink_xfs(dentry):
	try:
		inode = dentry.d_inode
		ip = readSU("struct xfs_inode", container_of(inode, "struct xfs_inode", "i_vnode"))
		flags = ip.i_df.if_flags
		if flags & XFS_IFINLINE:
			link = ip.i_df.if_u1.if_data
			return link
		else:
			return "unkown (xfs symlink not inline)"
	except Exception as e:
		print("error with readlink_xfs: {}".format(e))
		pass
	return "unknown"

def readlink_kernfs(dentry):
	try:
		inode = dentry.d_inode
		kn = readSU("struct kernfs_node", inode.i_private)
		parent = kn.parent
		target = kn.symlink.target_kn

		backward = ""
		forward = ""

		base = parent
		while base.parent:
			kn = target.parent
			while kn.parent and base != kn:
				kn = kn.parent

			if base == kn:
				break
			backward = "../" + backward
			base = base.parent

		kn = target
		while kn.parent and kn != base:
			forward = "/" + kn.name + forward
			kn = kn.parent
#	print("backward: {}, forward: {}".format(backward, forward))
		return backward + forward[1:]
	except Exception as e:
		print("error in kernfs_getlink: {}".format(e))
		pass
	return "unknown"

def hlist_entry(addr, stype, member):
	si = SUInfo(stype)
	offset = si[member].offset
	return readSU(stype, addr - offset)

_PIDTYPE = EnumInfo("enum pid_type")
# proc_fd(inode) {PROC_I(inode)->fd
# /proc/<pid>/fd/# =>
#  fd = PROC_I(inode)->fd
# struct file *__fget_files(struct files_struct *files, unsigned int fd, fmode_t mask, unsigned int refs) {
#  file = files_lookup_fd_rcu(files, fd)
#  if (file)
# struct file *fget_task(task_struct *task, unsigned int fd) { return __fget_files(task->files, fd, 0, 1);
def pid_task(pid, pid_type):
	try:
#		print("in pid_task(pid: 0x{:016x}".format(pid))

		first = pid.tasks[pid_type].first #is an hlist_node
	except Exception as e:
		print("error in pid_task: {}".format(e))
		pass
		return "unknown"
	try:
		# return hlist_entry(first, struct task_struct, pid_links[type]
#		print("pid {:016x} first: {:016x}".format(pid, first))

		tk = container_of(first, "struct task_struct", "pid_links") #pid_links[type]?
#		print("tk: {:016x}".format(tk))
		return tk

	except Exception as e:
		print("error getting task for pid: {}".format(e))
		pass
	return 0

def get_pid_task(pid, pid_type):
	try:
		if DEBUG >= 2: print("in get_pid_task; pid: 0x{:016x}".format(pid))
	except Exception as e:
		print("error 1 in get_pid_task: {}".format(e))
		pass
	try:
		return pid_task(pid, pid_type)
	except Exception as e:
		print("error in get_pid_task: {}".format(e))
		pass
	return 0
def PROC_I(inode):
	try:
		return container_of(inode, "struct proc_inode", "vfs_inode")
	except Exception as e:
		print("error in PROC_I: {}".format(e))
		sys.exit()
		pass
	return 0

def proc_pid(inode):
	try:
		if DEBUG >= 2: print("in proc_pid(inode: 0x{:016x}) - PROC_I(inode): 0x{:016x}".format(inode, PROC_I(inode)))
		return PROC_I(inode).pid
	except Exception as e:
		print("error in proc_pid(): {}".format(e))
		pass
	return 0
def get_proc_task(inode):
	try:
		if DEBUG >= 2: print("in get_proc_task(inode: 0x{:016x})".format(inode))
		return get_pid_task(proc_pid(inode), _PIDTYPE.PIDTYPE_PID)
	except Exception as e:
		print("error in get_proc_task: {}".format(e))
		pass
def PDE(inode):
	try:
		return PROC_I(inode).pde
	except:
		pass
	return 0

# proc_fd_show
def file_dentry(f):
	if f == 0:
		return 0
	try:
		return f.f_path.dentry
	except:
		pass
	try:
		return f.f_dentry
	except Exception as e:
		print("could not read (struct file*)0x{:016x}: {}".format(f, e))
		pass
	return 0

def dentry_get_pathname(dentry):
	return get_pathname(dentry, 0)

def dentry_get_all_paths(dentry, vfsmnt = 0):
#	print("in dentry_get_all_paths(dentry: 0x{:016x}, vfsmnt: 0x{:016x}".format(dentry, vfsmnt))
	ilvl = 0
	vfsmnt_list = []
	all_paths = []

	if DEBUG >= 1: print("{}(struct dentry *)0x{:016x}".format(indent(ilvl), dentry), end='')
	if vfsmnt:
#		print(", (struct vfsmnt *)0x{:016x}".format(vfsmnt), end='')
#		vfsmnt_list.append(readSU("struct vfsmount", vfsmnt))

		return [ get_pathname(dentry, vfsmnt) ]

	try:
		dentry = readSU("struct dentry", dentry)
	except Exception as e:
		print("exception in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
		print("\nexception in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
		traceback.print_tb(sys.exc_info()[2])
		print("")
		pass
		return

	sb = dentry.d_sb
	print(", (struct super_block *)0x{:016x}".format(sb))

	try:
		if vfsmnt:
			pathname = get_pathname(dentry, vfsmnt)
			if DEBUG >= 1: mount = readSU("struct mount", container_of(vfsmnt, "struct mount", "mnt"))
			if DEBUG >= 1: print(" - (struct mount *)0x{:016x} - (struct vfsmount *)0x{:016x} - flags: 0x{:04x} - {}".format(
				mount, vfsmnt, vfsmnt.mnt_flags, pathname))
			all_paths.append(pathname)
		else:
			mount_list = []

			sb = dentry.d_sb
			l = readlistByHead(sb.s_mounts)

			if DEBUG >= 1: print(" l has {} entries".format(len(l)))
			for le in l:
				mount = readSU("struct mount", container_of(le, "struct mount", "mnt_instance"))
#				mount_list.append(readSU(container_of(l, "mount", "mnt_instance"), "struct mount"))
				mount_list.append(mount)

			for mount in mount_list:
				pathname = get_pathname(dentry, mount.mnt)
#				if DEBUG >= 1: print(" - (struct mount *)0x{:016x} - (struct vfsmount *)0x{:016x} - flags: 0x{:04x} - {}".format(
				print(" - (struct mount *)0x{:016x} - (struct vfsmount *)0x{:016x} - flags: 0x{:04x} - {}".format(
					mount, mount.mnt, mount.mnt.mnt_flags, pathname))
				if not pathname in all_paths: all_paths.append(pathname)


#			vfsmnt_list.append(mount.mnt)
#			dl = readSUListFromHead(i_dentry, "d_alias", "struct dentry")

	except Exception as e:
		try:
			exc_info = sys.exc_info()
			print("exception in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
			traceback.print_tb(sys.exc_info()[2])
			print("")

			pass
		finally:
			traceback.print_exception(*exc_info)
			del exc_info

#		for vfsmnt in vfsmnt_list:
#			print(" - (struct vfsmnt *)0x{:016x} - flags: {:04x} - {}".format(vfsmnt, vfsmnt.mnt_flags, get_pathname(dentry, vfsmnt)))
	return all_paths


def path_get_pathname(p):
	try:
		return get_pathname(p.dentry, p.mnt)
	except Exception as e:
		print("failed in path_get_pathname: {}".format(e))
		pass
	try:
		return get_pathname(p.dentry, 0)
	except:
		pass
	return [ "unknown" ]


def readlink_proc_fd(dentry):
#	print("in readlink_proc_fd(dentry: 0x{:016x})".format(dentry))
	try:
		inode = dentry.d_inode
		pi = PROC_I(inode)

		fd = pi.fd

		tk = get_proc_task(inode)
#		print("back in readlink_proc_fd...  task: 0x{:016x}".format(tk))
		tk = readSU("struct task_struct", tk)

		files = tk.files
#		print("struct files_struct: 0x{:016x}".format(files))
#		print("files.fdt: 0x{:016x}".format(files.fdt))
#		print("files.fdt.fd: 0x{:016x}".format(files.fdt.fd))
		f = files.fdt.fd[fd]
		f = readSU("struct file", f)
		target_dentry = file_dentry(f)
#		print("here 15; target_dentry: 0x{:016x}".format(target_dentry))
		if target_dentry:
#			return dentry_get_pathname(target_dentry)
			return dentry_get_all_paths(target_dentry)
	except Exception as e:
		exc_info = sys.exc_info()
		print("error getting path in in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
		traceback.print_tb(sys.exc_info()[2])
		pass
	return [ "unknown" ]

# inode->i_op => proc_pid_link_inode_operations
# proc_inode.pid,fd  
# proc_inode.op.proc_get_link = proc_fd_link
# dentry -> tid_fd_dentry_operations
# proc_

def readlink_proc(dentry):
#	print("in readlink_proc(dentry: 0x{:016x}".format(dentry))

	try:
		inode = dentry.d_inode
	except Exception as e:
		print("exception in readlink_proc: {}".format(e))

		return [ "unknown" ]
#	sys.exit()
#	return dentry_get_pathname(dentry)

	try:
		inode = dentry.d_inode
		pi = PROC_I(inode)
#		print("here; pi: 0x{:016x}".format(pi))
#		print("pi.fd: {}".format(pi.fd))
		if pi and pi.fd:
			return readlink_proc_fd(dentry)
#		sys.exit()
	except Exception as e:
		print("error in readlink_proc: {}".format(e))
		sys.exit()
		pass

	try:
		inode = dentry.d_inode
		pi = PROC_I(inode)
		if pi.pid:
#			return readlink_proc_fd(dentry)
			return [ "unknown" ]

		pde = PDE(inode)
		if pde == 0:
			return [ "<name freed>" ]
		return [ SmartString(pde.data) ]
	except Exception as e:
		print("error in readlink_proc(): {}".format(e))
		pass
	return [ "unknown" ]
def readlink_simple(dentry):
	try:
		inode = dentry.d_inode
		if inode.i_link:
			return inode.i_link
	except:
		pass
	return [ "unknown" ]
def readlink_tmpfs(dentry):
	return readlink_simple(dentry)


# difference between inode_operations.get_link and inode_operations.readlink?
#
#	proc_map_files_link_inode_operations      readlink = 0xffffffff9c7b4de0
#	proc_pid_link_inode_operations    readlink = 0xffffffff9c7b4de0
#	proc_ns_link_inode_operations     readlink = 0xffffffff9c7bcef0

# likely symlinks
#	proc_link_inode_operations        get_link = 0xffffffff9c7b25e0
#	proc_pid_link_inode_operations    get_link = 0xffffffff9c7b4f70
#	proc_map_files_link_inode_operations      get_link = 0xffffffff9c7b4f90
#	proc_thread_self_inode_operations         get_link = 0xffffffff9c7bd3a0
#	proc_ns_link_inode_operations     get_link = 0xffffffff9c7bd130
#	proc_self_inode_operations        get_link = 0xffffffff9c7bd1e0
#	shmem_symlink_inode_operations    get_link = 0xffffffff9c6972d0
#	page_symlink_inode_operations     get_link = 0xffffffff9c739f00
#	simple_symlink_inode_operations   get_link = 0xffffffff9c75b5e0
#	proc_link_inode_operations        get_link = 0xffffffff9c7b25e0
#	proc_map_files_link_inode_operations      get_link = 0xffffffff9c7b4f90
#	proc_pid_link_inode_operations    get_link = 0xffffffff9c7b4f70
#	proc_ns_link_inode_operations     get_link = 0xffffffff9c7bd130
#	proc_self_inode_operations        get_link = 0xffffffff9c7bd1e0
#	proc_thread_self_inode_operations         get_link = 0xffffffff9c7bd3a0
#	configfs_symlink_inode_operations         get_link = 0xffffffff9c7cbad0
#	autofs_symlink_inode_operations   get_link = 0xffffffff9c7d3130
#	debugfs_symlink_inode_operations          get_link = 0xffffffff9c75b5e0
#	xfs_inline_symlink_inode_operations       get_link = 0xffffffffc03aa370 <xfs_vn_get_link_inline>
#	xfs_symlink_inode_operations      get_link = 0xffffffffc03aa2d0 <xfs_vn_get_link>
def readlink(dentry):
	try:
		inode = dentry.d_inode
		sb = inode.i_sb
		fstype = sb.s_type.name
	except Exception as e:
		print("error in readlink: {}".format(e))
		pass

	if fstype == "xfs":
		return readlink_xfs(dentry)
	if fstype == "sysfs":
		return readlink_kernfs(dentry)
	if fstype == "proc":
		return readlink_proc(dentry)
	if fstype == "tmpfs" or fstype == "devtmpfs":
		return readlink_tmpfs(dentry)

	return [ "unknown" ]

def qstr(addr):
	try:
		q = readSU("struct qstr", long(addr))
		len = q.len
		if len:
			return readmem(q.name, q.len)
		return ""
	except:
		print("hmm. some exception reding string")
#		raise
		pass
	return ""

# takes path, dentry, inode
def output_stat_info(path, dentry, inode):
	if dentry == 0: return

	if inode == 0:
		if not show_stale: return
		print("{:11s}  dentry: 0x{:016x}, {} (stale)".format(
			"???????????", dentry, path))
		print("zero inode.  dentry: {}".format(dentry))
		print("path:  {}".format(path))
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
			itype = None

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

	if itype == S_IFLNK:
		link_targets = readlink(dentry)
		mode_type_string = "{} => ".format(mode_type_string)
		first = True
		for link_target in link_targets:
			if first:
				mode_type_string = "{} => {}".format(mode_type_string, link_target)
				first = False
			else:
				mode_type_string = "{}, {}".format(mode_type_string, link_target)

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


def check_d_child(dentry):
	try:
#		childs = dentry.d_child
		childs = dentry.d_u

		child_list = readListByHead(childs)
		if len(child_list):
			print("dentry 0x{:016x} has {} 'd_child's".format(dentry, len(child_list)))
	except:
		pass

def check_d_alias(dentry):
	try:
		aliases = dentry.d_alias

		alias_list = readListByHead(aliases)
		if len(alias_list):
			print("dentry 0x{:016x} has {} aliases".format(dentry, len(alias_list)))
	except:
		pass


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

#	print("in find_recurse")
#	subdirs_offset = container_of(0, "struct dentry", "d_u")
#	subdirs_offset = container_of(0, "struct dentry", "d_subdirs")
	subdirs_offset = container_of(0, "struct dentry", "d_child")

	try:
		d_subdirs_head = int(dentry.d_subdirs)
		if d_subdirs_head == 0:
			return
	except:
		sys.exit()

	next = d_subdirs_head
	while 42:
		try:
			next = readPtr(next)
		except crash.error as e:
			print("error: {}".format(e))
			print(e)
			break
#		print("here 7 - next: 0x{:016x}, head: 0x{:016x}".format(next, d_subdirs_head))
		if (next == 0) or (next == d_subdirs_head):
			break
		try:
			dentry = readSU("struct dentry", next + subdirs_offset)
			inode = dentry.d_inode
		except Exception as e:
			print("error in find_recurse: {}".format(e))
			raise
			inode = 0
			pass
		dentry_name = get_dentry_name(dentry)
		if len(dentry_name) == 0:
			continue

		new_path = path + "/" + dentry_name
		output_stat_info(new_path, dentry, inode)

#		check_d_alias(dentry)
#		check_d_child(dentry)

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

	path = "0x{:016x}({})".format(dentry, dentry_name)

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
