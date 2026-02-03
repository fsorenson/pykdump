#!/usr/bin/python

import sys
import inspect
from pykdump.API import *
from crash import get_pathname
import traceback

def ind(i):
    return "{}".format(' ' * 4 * i)

def arg_value(arg):
	try:
		if '.' in arg:
			return float(arg)
		if arg.lower().startswith('0x'):
			return int(arg, 16)
		if arg.startswith('0') and all(c in string.octdigits for c in arg):
			return int(arg, 8)
#		if all(c in string.intdigits for c in arg): ### stupid python doesn't have string.intdigits?
		if all(c in '0123456789' for c in arg):
				return int(arg, 10)
		return int(arg, 16)
	except ValueError:
		return 0

def file_inode(filp):
	try:
		filp = readSU("struct file", filp)
	except Exception as ex:
		pass
		return 0
	try:
		return filp.f_inode
	except Exception as ex:
		try:
			dentry = readSU("struct dentry", file_get_dentry(filp))
			return dentry.d_inode
		except Exception as ex2:
			print("error in file_inode({:016x}): {}".format(dentry, ex2))
			pass
			return 0
		pass
	return 0


# TODO: show_mark_fhandle in fs/notify/fdinfo.c
def show_mark_fhandle(inode):
	print("fhandle NOT IMPLEMENTED", end='')

def fsnotify_conn_inode(conn):
	return readSU("struct inode", container_of(conn.obj, "struct inode", "i_fsnotify_marks"))

def fsnotify_conn_mount(conn):
	return readSU("struct mount", container_of(conn.obj, "struct mount", "mnt_fsnotify_marks"))

def fsnotify_conn_sb(conn):
	return readSU("struct super_block", container_of(conn.obj, "struct super_block", "s_fsnotify_marks"))

#include/uapi/linux/inotify.h
#define IN_ACCESS               0x00000001      /* File was accessed */
#define IN_MODIFY               0x00000002      /* File was modified */
#define IN_ATTRIB               0x00000004      /* Metadata changed */
#define IN_CLOSE_WRITE          0x00000008      /* Writtable file was closed */
#define IN_CLOSE_NOWRITE        0x00000010      /* Unwrittable file closed */
#define IN_OPEN                 0x00000020      /* File was opened */
#define IN_MOVED_FROM           0x00000040      /* File was moved from X */
#define IN_MOVED_TO             0x00000080      /* File was moved to Y */
#define IN_CREATE               0x00000100      /* Subfile was created */
#define IN_DELETE               0x00000200      /* Subfile was deleted */
#define IN_DELETE_SELF          0x00000400      /* Self was deleted */
#define IN_MOVE_SELF            0x00000800      /* Self was moved */
#define IN_ALL_EVENTS	(IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | \
#			 IN_CLOSE_NOWRITE | IN_OPEN | IN_MOVED_FROM | \
#			 IN_MOVED_TO | IN_DELETE | IN_CREATE | IN_DELETE_SELF | \
#			 IN_MOVE_SELF)
#define IN_ONESHOT		0x80000000	/* only send event once */
#define IN_EXCL_UNLINK		0x04000000	/* exclude events on unlinked objects */
#define INOTIFY_USER_MASK (IN_ALL_EVENTS | IN_ONESHOT | IN_EXCL_UNLINK)

#crash> px (0x00000001+0x00000002+0x00000004+0x00000008+0x00000010+0x00000020+0x00000040+0x00000080+0x00000100+0x00000200+0x00000400+0x00000800+0x80000000+0x04000000)
#$2 = 0x84000fff
INOTIFY_USER_MASK = 0x84000fff

def inotify_mark_user_mask(fsn_mark):
	return fsn_mark.mask & INOTIFY_USER_MASK

# FSNOTIFY_MARK_FLAGS from include/linux/fsnotify_backend.h
FSNOTIFY_MARK_FLAG_IGNORED_SURV_MODIFY	= 0x01
FSNOTIFY_MARK_FLAG_ALIVE		= 0x02
FSNOTIFY_MARK_FLAG_ATTACHED		= 0x04
#include/uapi/linux/fanotify.h
FAN_MARK_FLAGS_C = '''
/* flags used for fanotify_modify_mark() */
#define FAN_MARK_ADD            0x00000001
#define FAN_MARK_REMOVE         0x00000002
#define FAN_MARK_DONT_FOLLOW    0x00000004
#define FAN_MARK_ONLYDIR        0x00000008
/* FAN_MARK_MOUNT is            0x00000010 */
#define FAN_MARK_IGNORED_MASK   0x00000020
#define FAN_MARK_IGNORED_SURV_MODIFY    0x00000040
#define FAN_MARK_FLUSH          0x00000080
/* FAN_MARK_FILESYSTEM is       0x00000100 */

/* These are NOT bitwise flags.  Both bits can be used togther.  */
#define FAN_MARK_INODE          0x00000000
#define FAN_MARK_MOUNT          0x00000010
#define FAN_MARK_FILESYSTEM     0x00000100

/* These are NOT bitwise flags.  Both bits can be used togther.  */
#define FAN_MARK_INODE          0x00000000
#define FAN_MARK_MOUNT          0x00000010
'''
FAN_MARK_FLAGS = CDefine(FAN_MARK_FLAGS_C)

def fanotify_fdinfo(mark):
	mflags = 0
	if mark.flags & FSNOTIFY_MARK_FLAG_IGNORED_SURV_MODIFY:
		mflags = mflags | FAN_MARK_FLAGS['FAN_MARK_IGNORED_SURV_MODIFY']
	if mark.connector.type == enumerator_value("FSNOTIFY_OBJ_TYPE_INODE"):
		inode = fsnotify_conn_inode(mark.connector)
		print("inode: 0x{:016x}  ".format(inode), end='')
		if not inode:
			return
		print("fanotify ino:{:x} sdev:{:x} mflags:{:x} mask:{:x} ignored_mask:{:x} ".format(
			inode.i_ino, inode.i_sb.s_dev, mflags, mark.mask, mark.ignored_mask), end='')
		show_mark_fhandle(inode)
		print("")
	elif mark.connector.type == enumerator_value("FSNOTIFY_OBJ_TYPE_VFSMOUNT"):
		mnt = fsnotify_conn_mount(mark.connector)
		print("fanotify mnt_id:{:x} mflags:{:x} mask:{:x} ignored_mask:{:x}".format(
			mnt.mnt_id, mflags, mark.mask, mark.ignored_mask))
	elif mark.connector.type == enumerator_value("FSNOTIFY_OBJ_TYPE_SB"):
		sb = fsnotify_conn_sb(mark.connector)
		print("fanotify sdev:{:x} mflags:{:x} mask:{:x} ignored_mask:{:x}".format(
			sb.s_dev, mflags, mark.mask, mark.ignored_mask))

def inotify_fdinfo(mark):
	mark = readSU("struct fsnotify_mark", mark)
	if not mark or not mark.connector:
		print("invalid inotify mark connector")
		return
	if (mark.connector.type != enumerator_value("FSNOTIFY_OBJ_TYPE_INODE")):
		print("unexpected connector type")
		return

	inode_mark = readSU("struct inotify_inode_mark", container_of(mark, "struct inotify_inode_mark", "fsn_mark"))
	inode = fsnotify_conn_inode(mark.connector)
	print("inode: 0x{:016x}  ".format(inode), end='')
	if inode:
		print("inotify wd:{:x} ino:{:x} sdev:{:x} mask:{:x} ignored_mask:0 ".format(
			inode_mark.wd, inode.i_ino, inode.i_sb.s_dev, inotify_mark_user_mask(mark)), end='')
		show_mark_fhandle(inode)
		print("")

def notify_show_fdinfo(file, show):
	group = readSU("struct fsnotify_group", file.private_data)
	for mark in readSUListFromHead(group.marks_list, "g_list", "struct fsnotify_mark"):
		print("mark: 0x{:016x}  ".format(mark), end='')
		show(mark)

def inotify_show_fdinfo(file):
	notify_show_fdinfo(file, inotify_fdinfo)

def fanotify_show_fdinfo(file):
	group = readSU("struct fsnotify_group", file.private_data)
	print("fanotify flags:%x event-flags:%x".format(group.fanotify_data.flags, group.fanotify_data.f_flags))

	notify_show_fdinfo(file, fanotify_fdinfo)



def real_mount(vfsmnt):
	return readSU("struct mount", container_of(vfsmnt, "struct mount", "mnt"))

def display_fdinfo(addr):
	file = readSU("struct file", addr)
	fop = file.f_op

	print("file: 0x{:016x}".format(file))
#	print(" f_op is 0x{:016x}: {}".format(fop, addr2sym(fop)))

	print("pos:    {}".format(file.f_pos))
	print("flags:  0{:o}".format(file.f_flags))
	print("mnt_id: {}".format(real_mount(file.f_path.mnt).mnt_id))

#	show_fd_locks?

	if file.f_op and not file.f_op.show_fdinfo:
		return

	fops = addr2sym(file.f_op)
	if fops == "inotify_fops":
		print("inotify type")
		inotify_show_fdinfo(file)
	elif fops == "fanotify_fops":
		print("fanotify type")
		fanotify_show_fdinfo(file)
	else:
		print("unknown type")


	print("")



if __name__ == "__main__":
	for addr in sys.argv[1:]:
		addr = arg_value(addr)
		display_fdinfo(addr)

# vim: sw=4 ts=4 noexpandtab
