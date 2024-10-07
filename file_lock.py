#!/usr/bin/python

from __future__ import print_function

import sys, os

if __name__ == "__main__":
	mypath = os.path.dirname(os.path.realpath(sys.argv[0]))
	check_paths = [mypath, "/cores/crashext/epython/"]
	for p in check_paths:
		if os.path.isdir(p):
			if p not in sys.path:
				sys.path.append(p)

#from misc.percpu import get_per_cpu
from pykdump.API import *
from pykdump.Generic import SUInfo
from LinuxDump.Tasks import TaskTable
from LinuxDump.inet.proto import *
from libs.sorenson import *


from fs_lib import *
try:
	from rpc_credcache import show_cred_short
except Exception as ex:
	pass

@struct_printer
def pp_struct_file_lock(file_lock, rlvl, ilvl):
	print("{}file_lock stuff, dude".format(indent_str(ilvl)))



# stolen from skywalker...  needs to go into a lib
class get_per_cpu_foo():
	def __init__(self):
		self.cpu      = {}
		self.raw_list = exec_crash_command("p __per_cpu_start").split("\n")
		self.parse_list()

	def parse_list(self):
		count = 0
		for entry in self.raw_list:
			if ":" in entry:
				if "ff" in entry:
					self.cpu[count] = "0x" + entry.split()[-1]
					count += 1
		self.count = count

	def per_cpu_ptr(self, cpu, pointer):
		return int(self.cpu[cpu], 16) + pointer

	def per_cpu_struct(self, cpu, pointer, structtype):
		return readSU("struct " + structtype, (int(self.cpu[cpu], 16) + int(pointer)))

	def sum_values(self, struct):
		sum = 0
		for cpu in range(0, self.count):
			sum += readU64(self.per_cpu_ptr(cpu, struct))
		return sum

	def __repr__(self):
		retstr = "per-cpu:"
		for selectedcpu in self.cpu.keys():
			retstr = "%s\n%s%3s: %s" %(retstr, SPACER, selectedcpu, self.cpu[selectedcpu])
		return retstr


SB_FLAGS_C = '''
#define MS_RDONLY       0
#define MS_NOSUID       1
#define MS_NODEV        2
#define MS_NOEXEC       3
#define MS_SYNCHRONOUS  4
#define MS_REMOUNT      5
#define MS_MANDLOCK     6
#define MS_DIRSYNC      7
#define MS_NOATIME      10
#define MS_NODIRATIME   11
#define MS_BIND         12
#define MS_MOVE         13
#define MS_REC          14
#define MS_VERBOSE      15

#define MS_SILENT       15
#define MS_POSIXACL     16
#define MS_UNBINDABLE   17
#define MS_PRIVATE      18
#define MS_SLAVE        19
#define MS_SHARED       20
#define MS_RELATIME     21
#define MS_KERNMOUNT    22
#define MS_I_VERSION    23
#define MS_STRICTATIME  24
#define MS_SNAP_STABLE  27
#define MS_BORN         29
#define MS_ACTIVE       30
#define MS_NOUSER       31
'''
SB_FLAGS = CDefine(SB_FLAGS_C)


FL_TYPE_C = '''
#define FL_POSIX        1
#define FL_FLOCK        2
#define FL_DELEG        4       /* NFSv4 delegation */
#define FL_ACCESS       8       /* not trying to lock, just looking */
#define FL_EXISTS       16      /* when unlocking, test for existence */
#define FL_LEASE        32      /* lease held on this file */
#define FL_CLOSE        64      /* unlock on close */
#define FL_SLEEP        128     /* A blocking lock */
#define FL_DOWNGRADE_PENDING    256 /* Lease is being downgraded */
#define FL_UNLOCK_PENDING       512 /* Lease is being broken */
'''
FL_TYPE = CDefine(FL_TYPE_C)

FL_RDWR_C = '''
#define F_RDLCK         0
#define F_WRLCK         1
#define F_UNLCK         2
'''
FL_RDWR = CDefine(FL_RDWR_C)

FL_MAND_C = '''
#define LOCK_MAND       32      /* This is a mandatory flock ... */
#define LOCK_READ       64      /* which allows concurrent read operations */
#define LOCK_WRITE      128     /* which allows concurrent write operations */
#define LOCK_RW         192     /* which allows concurrent read & write ops */
'''
FL_MAND = CDefine(FL_MAND_C)

OFFSET_MAX = 0x7FFFFFFFFFFFFFFF

def check_fl_type(fl, type):
	if fl:
		try:
			flags = readSU("struct file_lock", fl).fl_flags
			return (flags & type) != 0
		except Exception as ex:
			pass
	return 0

def IS_POSIX(fl):
	return check_fl_type(fl, FL_TYPE['FL_POSIX'])

def IS_FLOCK(fl):
	return check_fl_type(fl, FL_TYPE['FL_FLOCK'])

def IS_LEASE(fl):
	return check_fl_type(fl, FL_TYPE['FL_LEASE'])

def fl_type_get_str(fl_type):
	ret = '???'
	if fl_type == FL_RDWR['F_RDLCK']: ret = 'F_RDLCK'
	elif fl_type == FL_RDWR['F_WRLCK']: ret = 'F_WRLCK'
	elif fl_type == FL_RDWR['F_UNLCK']: ret = 'F_UNLCK'

	return ret

def lease_breaking(fl):
	try:
		flags = readSU("struct file_lock", fl).fl_flags
		return flags & (FL_TYPE['FL_UNLOCK_PENDING'] | FL_TYPE['FL_DOWNGRADE_PENDING'])
	except Exception as ex:
		pass
	return 0


def file_get_dentry(filp):
	try:
		return Deref(filp.f_dentry)
	except KeyError:
		pass
	try:
		return Deref(filp.f_path.dentry)
	except: pass
	return 0

def broken_file_inode(filp):
	try:
		return readSU("struct file", filp).f_inode
	except Exception as ex:
		pass
	return 0

def file_inode(filp):
#def file_get_inode(filp):
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

def file_get_inode(filp):
	return file_inode(filp)

def file_get_vfsmnt(filp):
	try:
		return Deref(filp.f_vfsmnt)
	except KeyError:
		return Deref(filp.f_path.mnt)

def file_get_fstype_string(filp):
	try:
		return file_get_inode(filp).i_sb.s_type.name
	except Exception as ex:
		print("error getting filesystem type: {}".format(ex))
		pass
		return "Unknown"


def VALID_STRUCT(struct):
	tmp = 0
	try:
		foo = SUInfo("struct " + struct)
		return 1
	except TypeError:
		pass
	return 0

def new_get_pathname(dentry, vfsmount):
	return 0


def show_filp_info(filp):
	pathname = "???"
	try:
		filp = readSU("struct file", filp)

#		filp = fl.fl_file
		dentry = file_get_dentry(filp)
		vfsmnt = file_get_vfsmnt(filp)
		if dentry and vfsmnt:
			pathname = get_pathname(dentry, vfsmnt)
	except Exception as ex:
		print("error in show_filp_info:{}".format(ex))
		pass
	print("(struct file *)0x{:016x} - {} ".format(filp, pathname), end='')




def hlist_get_entries(hl, struct, member):
	if hl == 0:
		return []

	offset = -container_of(0, "struct " + struct, member)
	hlist_addrs = []
	try:
		first = hl.first
		while first != 0:
			hlist_addrs.append(first - offset)
			first = first.next
	except Exception as ex:
		print("error getting hlist entries: {}".format(ex))
		pass

	return hlist_addrs

def list_get_entries(head, struct, member):
	if head == 0:
		return []

	offset = -container_of(0, "struct " + struct, member)
	ret = []

	try:
		first = long(head)
		next = first
		while (next != 0):
			try:
				next = readPtr(next)
			except crash.error as e:
				print(e)
				break
			if (next == 0 or next == first):
				break
			ret.append(next - offset)
	except Exception as ex:
		print("error getting list entries: {}".format(ex))
		pass
	return ret

#define for_each_lock(inode, lockp) \
#for (lockp = &inode->i_flock; *lockp != NULL; lockp = &(*lockp)->fl_next)

def pid_nr_ns(pid, ns):
	nr = 0
	if pid and ns and (ns.level <= pid.level):
		upid = pid.numbers[ns.level]
		if (upid.ns == ns):
			nr = upid.nr
	return nr

# this stuff is too convoluted to be useful... just leave this crap out
#def task_pid(tsk):
#	return task.pids[PIDTYPE_PID].pid
#def task_active_pid_ns(tsk):
#	return ns_of_pid(task_pid(tsk))
#def pid_vnr(pid):
#	pid_nr_ns(pid, task_active_pid_ns(current))

def __IS_FLG(inode, flg):
	try:
		inode = readSU("struct inode", inode)
		return inode.i_sb.s_flags & flg
	except Exception as ex:
		pass
	return 0

def IS_MANDLOCK(ino):
	return __IS_FLG(ino, SB_FLAGS['MS_MANDLOCK'])

def __mandatory_lock(ino):
	return (ino.i_mode & (S_ISGID | S_IXGRP)) == S_ISGID

def mandatory_lock(ino):
	return IS_MANDLOCK(ino) and __mandatory_lock(ino)

def print_tasks_by_file(filp):
	try:
		tt = TaskTable()
	except Exception as ex:
		print("error getting task table: {}".format(ex))
		pass
		return

	try:
		tsks = tt.getByFile(filp)
		for tsk in tsks:
			print("{}pid={}, command={}".format(indent_str(2), tsk.pid, tsk.comm))
	except Exception as ex:
		print("error: {}".format(ex))
		pass

def pid_tsk(pid):
	try:
		tt = TaskTable();
	except Exception as ex:
		print("error getting task table: {}".format(ex))
		pass
	try:
		tsk = tt.getByTid(pid)
		return tsk
	except Exception as ex:
		print("error while finding task for pid {}: {}".format(pid, ex))
		pass

def show_blockers(blocker):
	blocker = readSU("struct file_lock", blocker)
	l = list_get_entries(blocker.fl_block, "file_lock", "fl_block")
#	list_get_entries(lockowners, "nlm_lockowner", "list")
	for e in l:
		print("blocker entry 0x{:016x}".format(e))
def show_waiters(blocker):
	blocker = readSU("struct file_lock", blocker)
	l = list_get_entries(blocker.fl_wait.task_list, "file_lock", "fl_wait")
#	list_get_entries(lockowners, "nlm_lockowner", "list")
	for e in l:
		print("blocker entry 0x{:016x}".format(e))



# see lock_get_status in fs/locks.c
def lock_get_status(fl):
#	print("lock_get_status(0x{:016x}))".format(fl))
	try:
		fl = readSU("struct file_lock", fl)
		fl_pid = fl.fl_pid

		if fl.fl_file:
			inode = file_inode(fl.fl_file)
		else:
			inode = 0

#		print("    ", end='')
		if IS_POSIX(fl):
			fl_flags = fl.fl_flags
#			mand_adv = "MANDATORY" if (inode and mandatory_lock(inode)) 
			print("{:6s} {}".format("ACCESS" if (fl_flags & FL_TYPE['FL_ACCESS']) else "POSIX ", "*NOINODE*" if (inode == 0) else "MANDATORY" if mandatory_lock(inode) else "ADVISORY "), end='')
		elif IS_FLOCK(fl):
			if fl.fl_type & FL_MAND['LOCK_MAND']:
				print("FLOCK  MSNFS     ", end='')
			else:
				print("FLOCK  ADVISORY  ", end='')
		elif IS_LEASE(fl):
			print("LEASE  ????????  ", end='')
		else:
			print("UNKNOWN UNKNOWN  ", end='')

		if fl.fl_type & FL_MAND['LOCK_MAND']:
			if (fl.fl_type & FL_MAND['LOCK_READ']):
				str = "RW   " if (fl.fl_type & FL_MAND['LOCK_WRITE']) else "READ "
			else:
				str = "WRITE" if (fl.fl_type & FL_MAND['LOCK_WRITE']) else "NONE "
			print("{} ".format(str), end='')
		else:
			if (lease_breaking(fl)):
				str = "UNLCK" if (fl.fl_type & FL_RDWR['F_UNLCK']) else "READ "
			else:
				str = "WRITE" if (fl.fl_type & FL_RDWR['F_WRLCK']) else "READ "
			print("{} ".format(str), end='')

		# move pid display from here to later
		if inode:
#			print("pid={:<8d} {}:{} ".format(fl_pid, inode.i_sb.s_id, inode.i_ino), end='')
			print("{}:{} ".format(inode.i_sb.s_id, inode.i_ino), end='')
		else:
#			print("pid={:<8d} <none>:0 ".format(fl_pid), end='')
			print("<none>:0 ", end='')

		if IS_POSIX(fl):
			if (fl.fl_end == OFFSET_MAX):
				print("{} - EOF".format(fl.fl_start))
			else:
				print("{} - {}".format(fl.fl_start, fl.fl_end))
		else:
			print("0 - EOF")

		ptsk = pid_tsk(fl_pid)
		try:
			comm = ptsk.comm
		except:
			comm = "????"
			pass

		print("{}owner pid={}, comm = '{}'".format(indent_str(2), fl_pid, comm))
		try:
			print_tasks_by_file(fl.fl_file)
		except Exception as ex:
			print("error printing tasks for file_lock {:016x}: {}".format(fl, ex))
			pass
		show_lm_info(fl) # try to show lm-specific info

#		show_filp_info(fl.fl_file)
#		print("")
		if fl.fl_file:
			fst = file_get_fstype_string(fl.fl_file)
			if fst == "nfs" or fst=="nfs4":
				try:
					ctx = readSU("struct nfs_open_context", fl.fl_file.private_data)
					cred = ctx.cred
					show_cred_short(cred)
				except Exception as ex:
					print("error with nfs filesystem type: {}".format(ex))
					pass

#			def show_cred_short(cred_addr, jiffies=0, ilvl=1):
		show_blockers(fl)
		show_waiters(fl)

	except crash.error as e:
		print("An error occurred in lock_get_status: {}".format(e))
		pass


def format_sockaddr_in_ip(sa, proto=0):
	try:
		sa = readSU("struct sockaddr", sa)
		family = sa.sa_family

		if (family == P_FAMILIES.PF_INET):
			sai = readSU("struct sockaddr_in", sa)
			port = ntohs(sai.sin_port)
			addr_str = "{}".format(ntodots(sai.sin_addr.s_addr))

#			"%s:*" %(ntodots(ip))
		elif (family == P_FAMILIES.PF_INET6):
			sai6 = readSU("struct sockaddr_in6", sa)
			port = ntohs(sai6.sin6_port)
			addr_str = "{}".format(ntodots6(sai6.sin6_addr))
		else:
			return "UNKNOWN"


		if port:
			return "{}:{}".format(addr_str, port)
		else:
			return "{}:*".format(addr_str)
	except crash.error as e:
		print("An error occurred: {}".format(e))
	return "ADDRESS UNKNOWN"



def get_sym_addr(sym):
	try:
		addr = long(readSymbol(sym))
		return addr
	except Exception as ex:
		return 0

nlmsvc_lock_operations = get_sym_addr("nlmsvc_lock_operations")
lease_manager_ops = get_sym_addr("lease_manager_ops")
nfsd_lease_mng_ops = get_sym_addr("nfsd_lease_mng_ops")
nfsd_posix_mng_ops = get_sym_addr("nfsd_posix_mng_ops")

def show_nlm_lockowners(lockowners):
	try:
		lo_entries = list_get_entries(lockowners, "nlm_lockowner", "list")
		for lo in lo_entries:
			print("{}nlm_lockowner: 0x{:016x} - pid: {}".format(indent_str(2), lo, lo.pid))
	except Exception as ex:
		pass


def show_nlm_lockinfo(fl):
	try:
		nlm_host = readSU("struct nlm_host", fl.fl_owner)
		print("{}(struct nlm_host *)0x{:016x}".format(indent_str(1), nlm_host), end='')

		print(", '{}'".format(nlm_host.h_name), end='')

		h_addr = nlm_host.h_addr

#		addr_str = format_sockaddr_in_ip(nlm_host.h_addr, proto=nlm_host.h_proto)
#		addr_str = format_sockaddr_in_ip(h_addr, proto=h_proto)
#		print(", '{}'".format(addr_str), end='')
		try:
			print(", {} '{}'".format(PROTONAMES[nlm_host.h_proto], nlm_host.h_addrbuf), end='')
		except Exception as ex:
			pass
		try:
			print(", nodename={}".format(nlm_host.nodename), end='')
		except Exception as ex:
			pass

		try:
			show_nlm_lockowners(nlm_host.h_lockowners)
		except Exception as ex:
			print("error showing nlm lockowners: {}".format(ex))
			pass

		print("")
		filp = fl.fl_file

	except crash.error as e:
		print("An error occurred: {}".format(e))
		pass

def show_nfsd_posix_lockinfo(fl):
	try:
		nfs4_lockowner = readSU("struct nfs4_lockowner", fl.fl_owner)
		nfs4_stateowner = nfs4_lockowner.lo_owner
		nfs4_client = nfs4_stateowner.so_client

		cl_name = readmem(nfs4_client.cl_name.data, nfs4_client.cl_name.len)
		print("{}(struct nfs4_lockowner *)0x{:016x}".format(indent_str(1), nfs4_lockowner), end='')
		print(", '{}'".format(cl_name))
		print("{}** TODO: lockowners **".format(indent_str(1)))

	except crash.error as e:
		print("An error occurred: {}".format(e))
		pass

try:
	open_delegation_type4 = EnumInfo("enum open_delegation_type4")
except Exception as ex:
	open_delegation_types = None

def show_nfsd_lease_lockinfo(fl):
	try:
		nfs4_lockowner = readSU("struct nfs4_lockowner", fl.fl_owner)
		print("got the lo")
		nfs4_stateowner = nfs4_lockowner.lo_owner
		print("got the so")
		nfs4_client = nfs4_stateowner.so_client
		print("got the nfs4_client")

		cl_name = readmem(nfs4_client.cl_name.data, nfs4_client.cl_name.len)
		print("\t(struct nfs4_lockowner *)0x{:016x}".format(nfs4_lockowner), end='')
		print(", '{}'".format(cl_name))
		print("\t** TODO: lockowners **")

		lock_type = "UNKNOWN"
		if fl.fl_type == 0:
			lock_type = "F_RDLCK"
		elif fl.fl_type == 1:
			lock_type = "F_WRLCK"

		print("\tlease: {}".format(lock_type))

	except crash.error as e:
		print("An error occurred: {}".format(e))
		pass



STRUCT_STRINGS = """
struct nfs4_lockowner {
		    struct nfs4_stateowner lo_owner;
			    struct list_head lo_blocked;

struct nfs4_stateowner {
	struct list_head so_strhash;
	struct list_head so_stateids;
	struct nfs4_client *so_client;
	const struct nfs4_stateowner_operations *so_ops;
	atomic_t so_count;
	u32 so_seqid;
	struct xdr_netobj so_owner;
	struct nfs4_replay so_replay;
	bool so_is_open_owner;

struct nfs4_client {
	struct list_head cl_idhash;
	struct rb_node cl_namenode;
	struct list_head *cl_ownerstr_hashtbl;
	struct list_head cl_openowners;
	struct idr cl_stateids;
	struct list_head cl_delegations;
	struct list_head cl_revoked;
	struct list_head cl_lru;
	struct list_head cl_lo_states;
	struct xdr_netobj cl_name;
	nfs4_verifier cl_verifier;
	time_t cl_time;
	struct __kernel_sockaddr_storage cl_addr;
	bool cl_mach_cred;
	struct svc_cred cl_cred;
	clientid_t cl_clientid;
	nfs4_verifier cl_confirm;
	u32 cl_minorversion;
	struct nfs4_cb_conn cl_cb_conn;
	unsigned long cl_flags;
	struct rpc_cred *cl_cb_cred;
	struct rpc_clnt *cl_cb_client;
	u32 cl_cb_ident;
	int cl_cb_state;
	struct nfsd4_callback cl_cb_null;
	struct nfsd4_session *cl_cb_session;
	spinlock_t cl_lock;
	struct list_head cl_sessions;
	struct nfsd4_clid_slot cl_cs_slot;
	u32 cl_exchange_flags;
	atomic_t cl_refcount;
	unsigned long cl_cb_slot_busy;
	struct rpc_wait_queue cl_cb_waitq;
	struct net *net;
"""




def show_lm_info(fl):
	try:
		fl = readSU("struct file_lock", fl)

		if not fl.fl_lmops:
			return
		if fl.fl_lmops == nlmsvc_lock_operations:
			show_nlm_lockinfo(fl)
		elif fl.fl_lmops == nfsd_posix_mng_ops:
			show_nfsd_posix_lockinfo(fl)
		elif fl.fl_lmops == nfsd_lease_mng_ops:
			show_nfsd_lease_lockinfo(fl)
		else:
			print("UNKNOWN LOCK MANAGER")

	except crash.error as e:
		print("An error occurred: {}".format(e))
		pass
		return


# show locks attached to an inode, limiting to a filp if provided
def show_inode_locks(inode, filp=0):
	try:
		inode = readSU("struct inode", inode)
		print("(struct inode *)0x{:016x}".format(inode))
		next_fl = inode.i_flock
		while next_fl != 0:
			fl = next_fl
			next_fl = fl.fl_next

			if filp and (filp != fl.fl_file):
				continue

			print("(struct file_lock *)0x{:016x} ".format(fl), end='')

			try:
				lock_get_status(fl)
			except: pass

			print("bar")
			if fl.fl_owner:
				print("\tfl.fl_owner=0x{:016x}".format(fl.fl_owner))
#				continue
			print("next_fl={:016x}".format(next_fl))
	except crash.error as e:
		print("An error occurred in show_inode_locks: {}\n\tinode: 0x{:016x}, filp: 0x{:016x}".format(e, inode, filp))
		pass

def show_fd_locks(filp):
	try:
		filp = readSU("struct file", filp)

		show_filp_info(filp)
		print("\n\t", end='')
		print("(struct inode *)0x{:016x}".format(file_inode(filp)), end='')
		print("\n\t", end='')
		show_inode_locks(file_inode(filp), filp)

#		fl_type_str = fl_type_get_str(fl_type)
#		fl_owner = flock.fl_owner

		print("")

	except crash.error as e:
		print("An error occurred: {}".format(e))
		pass

def show_files_struct(fs):
	fs = readSU("struct files_struct", fs)
	print("{}(struct files_struct *)0x{:016x} - {}".format(
		indent_str(1), fs, fs))



file_lock_list = readSymbol("file_lock_list")
if is_percpu_symbol(file_lock_list):
	def get_file_lock_list():
		percpu = get_per_cpu()
		lock_entries = []

		for c in percpu.cpu.keys():
			i_addr = percpu.per_cpu_struct(c, file_lock_list, "hlist_head")
			try:
				new_ents = hlist_get_entries(i_addr, "file_lock", "fl_link")

				for e in new_ents:
					lock_entries.append(e)
			except Exception as ex:
				print("error reading file lock list: {}".format(ex))
				pass
		return lock_entries
else:
	def get_file_lock_list():
		return list_get_entries(file_lock_list, "file_lock", "fl_link")

def posix_owner_key(fl):
	fl = readSU("struct file_lock", fl)
	if fl.fl_lmops and fl.fl_lmops.lm_owner_key:
		printf("file_lock 0x{:016x} has owner key function 0x{:016x}".format(
			fl, fl.fl_lmops.lm_owner_key))
		return None
	else:
		print("fl: 0x{:016x}, fl.fl_owner: 0x{:016x}".format(fl, fl.fl_owner))
		print("addr of fl.fl_owner: 0x{:016x}".format(Addr(fl.fl_owner)))
		return Addr(fl.fl_owner)

if symbol_exists("blocked_hash"):
	def get_blocked_locks():
		blocked_hash = readSymbol("blocked_hash")
		blocked_locks = []
		i = 0

		for num, hl in enumerate(blocked_hash):
			entries = hlist_get_entries(hl, "file_lock", "fl_link")
			for entry_addr in entries:
				entry = readSU("struct file_lock", entry_addr)
				blocked_locks.append(entry)
		return blocked_locks
else:
	def get_blocked_locks():
		return []


def show_file_lock(fl):
	le = readSU("struct file_lock", fl)

	print("(struct file_lock *)0x{:016x} ".format(fl), end='')
	try:
		lock_get_status(fl)
		try:
			print("{}".format(indent_str(1)), end='')
			filp = readSU("struct file_lock", fl).fl_file

			show_filp_info(filp)
			print("")
			print("{}(struct inode *)0x{:016x}".format(indent_str(1), file_inode(filp)))

		except Exception as ex:
			print("error with file lock: {}".format(ex))
			pass
	except Exception as ex:
		print("error with lock entry list: {}".format(ex))
		pass

def show_lock_list(lock_entries):
	i = 0
	for fl in lock_entries:
		i += 1
		print("{}: ".format(i), end='')
		show_file_lock(fl)


def show_proc_locks():
	lock_entries = get_file_lock_list()

	print("{} locks found in file_lock_list".format(len(lock_entries)))
	show_lock_list(lock_entries)

def show_blocked_locks():
	blocked_locks = get_blocked_locks()

	if len(blocked_locks):
		print("{} blocked lock(s):".format(len(blocked_locks)))

	for bl in blocked_locks:
		print("{}(struct file_lock *)0x{:016x} - owner: 0x{:016x}".format(
			indent_str(1), bl, posix_owner_key(bl)))
		show_file_lock(bl)
		show_files_struct(posix_owner_key(bl))


if __name__ == "__main__":
	if len(sys.argv) > 1:
		for arg in sys.argv[1:]:
			addr = get_arg_value(arg)
			if addr != 0:
				show_fd_locks(addr)
	else:
		show_proc_locks()
		print("")
		show_blocked_locks()

# vim: sw=4 ts=4 noexpandtab
