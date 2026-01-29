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

# TODO: show_mark_fhandle in fs/notify/fdinfo.c
def show_mark_fhandle(inode):
	print("fhandle NOT IMPLEMENTED", end='')

def fsnotify_conn_inode(conn):
	return readSU("struct inode", container_of(conn.obj, "struct inode", "i_fsnotify_marks"))

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


def inotify_show_fdinfo(file):
	group = readSU("struct fsnotify_group", file.private_data)
	for mark in readSUListFromHead(group.marks_list, "g_list", "struct fsnotify_mark"):
		print("mark: 0x{:016x}  ".format(mark), end='')
		inotify_fdinfo(mark)


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

	fops = addr2sym(file.f_op)
	if fops == "inotify_fops":
		print("inotify type")
		inotify_show_fdinfo(file)
	else:
		print("unknown type")


	print("")



if __name__ == "__main__":
	for addr in sys.argv[1:]:
		addr = arg_value(addr)
		display_fdinfo(addr)

# vim: sw=4 ts=4 noexpandtab
