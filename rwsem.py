#!/usr/bin/python

from __future__ import print_function

#from fs_lib import *
#from dumpobj import *
from LinuxDump import *
from LinuxDump.Tasks import *
from LinuxDump.Tasks import TASK_STATE, TaskTable
from LinuxDump.BTstack import exec_bt
from pykdump.API import *
from LinuxDump.KernLocks import (decode_mutex)
import argparse

debug_script = False


def ind(i):
	return "{spaces}".format(spaces = ' ' * 4 * i)


#task_states = __get_states_from_array()

def enum_string(enum_name, val):
	str = "UNKNOWN"
	_enum_mapping = {}
	try:
		_S_enum_info = EnumInfo("enum " + enum_name)
		if _S_enum_info is None:
			return str
		_enum_key_list = sorted(_S_enum_info, key=lambda x: _S_enum_info[x])
		str = _enum_key_list[val]
	except Exception as ex:
		pass
	return str


def get_sym_addr(sym):
	try:
		addr = long(readSymbol(sym))
		return addr
	except Exception as ex:
		return 0

def addr_is_symbol(addr):
	try:
		sym = addr2sym(addr)
		if sym == None:
			return False
		return sym
	except:
		return False

def string_is_symbol(string):
	try:
		addr = sym2addr(string)
		if addr == None:
			return False
		return addr
	except:
		return False


def get_arg_value(arg):
	try:
		sym_addr = string_is_symbol(arg)

#		print("sym_addr '{}' = '{}'".format(arg, sym_addr))
		if (sym_addr) != 0:
			return sym_addr


		if '.' in arg:
			return float(arg)
		if arg.lower().startswith('0x'):
			return int(arg, 16)
		if arg.startswith('0') and all(c in string.octdigits for c in arg):
			return int(arg, 8)
#               if all(c in string.intdigits for c in arg): ### stupid python doesn't have string.intdigits?
		if all(c in '0123456789' for c in arg):
			return int(arg, 10)
		return int(arg, 16)
	except ValueError:
		return 0

def task_state_abbr(state):
	if state is TASK_STATE.TASK_RUNNING: return "RU"
	elif state == "TASK_RUNNING": return "RU"
	elif state == "TASK_INTERRUPTIBLE": return "IN"
	elif state == "TASK_UNINTERRUPTIBLE": return "UN"
	elif state == "TASK_STOPPED": return "ST"
	elif state == "TASK_TRACED": return "TR"

	if state == "TASK_ZOMBIE": return "TZ"
	if state == "EXIT_ZOMBIE": return "XZ"

	if state == "EXIT_DEAD": return "XD"
	if state == "TASK_DEAD": return "DE"

	if state == "TASK_WAKEKILL|TASK_UNINTERRUPTIBLE": return "KU"

	if state == "TASK_WAKEKILL": return "WK"
	elif state == "TASK_WAKING": return "WA"
	elif state == "TASK_PARKING": return "PK"
	else:
		return "?{}?".format(str(state))



def pp_time_ns(ns):
	s = int(ns / 1000000000)
#	ns %= 1000000000
	ns = int(ns % 1000000000)
	m = int(s / 60)
	s %= 60
	h = int(m / 60)
	m %= 60
	d = int(h / 24)
	h %= 24
	return "%d %2d:%02d:%02d.%09d" % (d, h, m, s, ns)

def pp_time_us(us):
	return pp_time_ns(us * 1000)[:-3]

def pp_time_ms(ms):
	return pp_time_ns(ms * 1000 * 1000)[:-6]

def pp_time_s(s):
	return pp_time_ns(s * 1000 * 1000 * 1000)[:-10]

def get_time_ms_pretty(t):
	return pp_time_ms(t)


def show_task_line_generic(task, this_pid=None):

	try:
		task = readSU("struct task_struct", task)
	except:
		return

	try:
		pid = task.pid
	except:
		return

	tt = TaskTable()
	t = tt.getByTid(pid)

	if t == None:
		return

	comm = task.comm
	state = task_state_abbr(t.state)
	lr = t.Last_ran
	basems = tt.basems
	delay = get_time_ms_pretty(basems - lr)
	if this_pid is not None and this_pid == pid:
		this_pid_str = "**"
	else:
		this_pid_str = "  "
	type_str = ""

	print("{}0x{:016x}  {:7d} {:s}{:16s} {st} {time}   {type_str}".format(
		ind(2), Addr(task), pid, this_pid_str, comm, st=state, time=delay, type_str=type_str))

try:
	WAKE_Q_TAIL = readSU("struct wake_q_node", 0x1)

	def wake_q_list(head):
		wq = []

		print("wake_q_head       = {:016x}".format(head))
		if head == WAKE_Q_TAIL:
			return wq
		head = readSU("struct wake_q_head", head)
		if head.first == head.lastp:
			return wq

		node = head.first

		print("wake_q_list first = {:016x}".format(node))
#		print("WAKE_Q_TAIL       = {:016x}".format(WAKE_Q_TAIL))
		while node and node != WAKE_Q_TAIL:
			try:
				next_node = node.Eval("next")
			except:
				break

			t = container_of(node, "struct task_struct", "wake_q")

			print("     node = {:016x}".format(node))
			print("     task = {:016x} ?".format(t))
			if t in wq:
				break
			wq.append(t)
			node = next_node

		return wq
except:
	def wake_q_list(head):
		return


def rwsem_count(rwsem):
	rwsem = readSU("struct rw_semaphore", rwsem)
	try:
		return rwsem.count.counter
	except:
		return rwsem.count


RWSEM_READER_OWNED = (1 << 0)
RWSEM_ANONYMOUSLY_OWNED = (1 << 1)
#define RWSEM_READER_OWNED      (1UL << 0)
#define RWSEM_ANONYMOUSLY_OWNED (1UL << 1)
def rwsem_owner(rwsem):
	rwsem = readSU("struct rw_semaphore", rwsem)

	try:
		o = (rwsem.owner.counter & 0xffffffffffffffff) & ~0x3
		return readSU("struct task_struct", o)
	except Exception as e:
#		print("exception: {}".format(e))
		pass
	try:
		return readSU("struct task_struct", rwsem.owner & ~0x3)
#		thing = rwsem.owner & ~0x3
#		print("returning the first thing: 0x{:016x}".format(thing))
#		return readSU("struct task_struct", readU64(rwsem.owner) & ~0x3)
	except:
		pass
	return 0

def reader_owned(rwsem):
	try:
		o = rwsem.owner.counter & 0xffffffffffffffff
		return (o & RWSEM_READER_OWNED) == RWSEM_READER_OWNED
	except:
		pass
	try:
		return (rwsem.owner & RWSEM_READER_OWNED) == RWSEM_READER_OWNED
	except:
		return 0
def anonymously_owned(rwsem):
	try:
		o = rwsem.owner.counter & 0xffffffffffffffff
		return (o & RWSEM_ANONYMOUSLY_OWNED) == RWSEM_ANONYMOUSLY_OWNED
	except:
		pass
	try:
		return (rwsem.owner & RWSEM_ANONYMOUSLY_OWNED) == RWSEM_ANONYMOUSLY_OWNED
	except:
		return 0


RWSEM_UNLOCKED_VALUE = 0x00000000
RWSEM_ACTIVE_MASK = 0x0000ffff
RWSEM_UNLOCKED_VALUE = 0x00000000
RWSEM_ACTIVE_BIAS = 0x00000001
RWSEM_WAITING_BIAS = (-RWSEM_ACTIVE_MASK-1)
RWSEM_ACTIVE_READ_BIAS = RWSEM_ACTIVE_BIAS
RWSEM_ACTIVE_WRITE_BIAS = (RWSEM_WAITING_BIAS + RWSEM_ACTIVE_BIAS)
def show_rwsem(semaddr, btpid=None, btwaiter=None):
	err = ""
	warning = ""

	tt = TaskTable()
	try:
		err = "readSU(rw_semaphore)"
		s = readSU("struct rw_semaphore", semaddr)
		count = rwsem_count(s)
		rcount = count & 0xffffffff
		wcount = count & 0xffffffff00000000
		owner = rwsem_owner(s)

#		owner_str = "unknown: 0x{:016x}".format(owner)

		if reader_owned(s):
			owner_str = ""
			if anonymously_owned(s):
				owner_str = "anonymous reader task - possibly:"

			t = tt.getByTid(owner.pid)
			if t:
				state = task_state_abbr(t.state)
				owner_str += "{} ({} - {:6d} - {})".format(owner, state, owner.pid, owner.comm)
			else:
				owner_str += "Invalid owner: 0x{:016x}".format(owner)
		elif count == 0:
			owner_str = "unlocked?"
		elif owner:
			t = tt.getByTid(owner.pid)
			if t:
				state = task_state_abbr(t.state)
				owner_str = "Write owner {} ({} - {:6d} - {})".format(owner, state, owner.pid, owner.comm)
			else:
				owner_str = "Invalid owner: 0x{:016x}".format(owner)
		else:
			owner_str = "unknown: 0x{:016x}".format(owner)

		wcount = "?"
		rcount = "?"
#		if wcount == 0xffffffff00000000:
#			wcount = "writer (or write waiter)"
#			if owner == 0x1:
#				warning += "{}WARNING: rwsem potentially inconsistent: counter indicates writer may own semaphore, but owner says held by reader".format(ind(2))
#		elif wcount == 0xfffffffe00000000:
#			wcount = "writer (or write waiter) + write waiter"
#			if owner == 0x1:
#				warning += "{}WARNING: rwsem inconsistent: counter indicates writer owns semaphore, but owner says held by reader".format(ind(2))
#		elif wcount == 0x0000000000000000:
#			wcount = "none"
#		else:
#			wcount = "ERROR"


		print("{}:".format(s))
#	if not count:
#		return

#		print("owner: {}".format(owner))

#		if owner == 0x0:
#			owner_str = ""
#		elif reader_owned(s):
#			owner_str = "owned by a reader"
#		else:
#			t = tt.getByTid(owner.pid)
#
#			print("here 4")
#			if t:
#				state = task_state_abbr(t.state)
#				owner_str = "Write owner {} ({} - {:6d} - {})".format(owner, state, owner.pid, owner.comm)
#			else:
#				owner_str = "Invalid owner: 0x{:016x}".format(owner)

		print("{}{}, counter: 0x{:016x}".format(ind(2), owner_str, count & 0xffffffffffffffff))


	except Exception as ex:
		print("{}exception with '{}': {}".format(ind(2), err, ex))
		pass
		return

	wl = []
	print("{}wait_list: {:016x} ?".format(ind(2), s.wait_list))
	try:
#		if Addr(s.wait_list.next):
#			wltemp = readList(Addr(s.wait_list.next))
		if Addr(s.wait_list) and Addr(s.wait_list) != s.wait_list.next:
			wltemp = readList(Addr(s.wait_list.next))
			for w in wltemp:
				if w == s.wait_list:
					break
				wl.append(readSU("struct rwsem_waiter", w))
	except Exception as ex:
		print("error reading rwsem_waiter list: {}".format(ex))
		pass
		return

	tt = None
	if (len(wl)):
		tt = TaskTable()

	print("{}waitlist: {}, write: {}, read count: {}".format(ind(2), len(wl), wcount, rcount))

	if warning != "":
		print(warning)

	for w in wl:
		task = w.task
#		task = container_of(w.task, "struct task_struct", "wake_entry")
#		task = container_of(w.task, "struct task_struct", "wake_entry")
#		print("*** wake_entry at {:016x} or at {:016x} ??".format(w, task))
		pid = -1
		if task != 0 and task != 1:
			try:
				pid = task.pid
				comm = task.comm
				t = tt.getByTid(pid)
				state = task_state_abbr(t.state)
				lr = t.Last_ran
#				basems = tt.basems
#				delay = get_time_ms_pretty(basems - lr)
				delay = get_time_ms_pretty(t.Ran_ago)
			except Exception as e:
				print("error: {}".format(e))
				pid = -1
				pass

		if btpid is not None and btpid == pid:
			this_pid_str = "**"
		else:
			this_pid_str = "  "
		if pid == -1:
			comm = "?????"
			state = "??"
			delay = "??"
			this_pid_str = "  "
		type = enum_string("rwsem_waiter_type", w.type)

		print("{}0x{:016x}  {:7d} {:s}{:16s} {st} {time}   {type}".format(ind(2), w, pid, this_pid_str, comm, st=state, time=delay, type=type))


#<djeffery> sorenson:  If it's the same issue, the there should be
#	a task in rwsem_down_read_failed
#		who has its rwsem_waiter struct not on the rwsem's wait list
#		and the rwsem_waiter.task pointer cleared to NULL.
# If there isn't a read waiter sleeping in that state, it's probably something different

def display_rwsem_info(bts, rwsem_addr, waiter_addr, wqh_addr):
	pid = None
	cmd = ''
	wqh = 0
	waiter = 0

#	if bts != 0:
#		pid = bts.pid
#		cmd = bts.cmd
#	else:
#		pid = None
#		cmd = ""

	rwsem = readSU("struct rw_semaphore", rwsem_addr)
	try:
		if wqh_addr:
			wqh = readSU("struct wake_q_head", wqh_addr)  ##### this is a wait_list, not a wake_q_head, isn't it? ***** FIXME
	except:
		wqh = False
		pass

#	waiter = readSU("struct rwsem_waiter", waiter_addr)
#	if waiter_addr and pid:
#		waiter = check_waiter_task_fuzzy(waiter_addr, pid)
#	print("did we find an rwsem_waiter for pid {} with address {:016x}: {:016x}?".format(
#		pid, waiter_addr, waiter))


#	print("pid {} '{}' may have an rwsem at {:016x}, waiter at {:016x}, wake_q_head at {:016x}".format(
#		pid, cmd, rwsem, waiter, wqh))
	show_rwsem(rwsem, btpid=pid)
	if waiter:
		print("{}(struct rwsem_waiter *)0x{:016x}".format(ind(1), waiter))
	if wqh:
		wq = wake_q_list(wqh)
		print("{}wake_q: {:016x} (len {})".format(ind(1), wqh, len(wq)))

		w_in_wq = False
		for w in wq:
			print("checking whether waiter {:016x} matches wq entry {:016x}".format(
				waiter, w))
			if w == waiter:
				w_in_wq = True
			show_task_line_generic(w, pid)
		if w_in_wq:
			print("waiter {:016x} is in wq {:016x}".format(waiter, wqh))
		elif waiter:
			print("could not find waiter {:016x} in wake_queue {:016x}".format(waiter, wqh))
#	check_pid_rwsem_waitlist(pid, waiter, rwsem) ## might be easier to just check w in wq above





#####

pid_max_max = get_sym_addr("pid_max_max")

if __name__ == "__main__":
	opts_parser = argparse.ArgumentParser()
	opts_parser.add_argument('rwsems', metavar='N', type=str, nargs='*',
			help='rwsemaphore addresses to display')
	opts_parser.add_argument('--rwsems', dest='rwsems', default=[], metavar='N', type=str, nargs='*',
			help='rwsem addresses to display')
	opts_parser.add_argument('--debug', '-d', dest='debug', default=[], action='store_true',
			help='show script debugging information')

	args = opts_parser.parse_args()
	if args.debug:
		debug_script = True

#	if len(args.addrs) > 0:
#		for arg in args.addrs:
#			addr = get_arg_value(arg)
#			if addr != 0:
#				addr_is_symbol(addr)
#				check_xfs_inode_locks(addr)
	if len(args.rwsems) > 0:
		for arg in args.rwsems:
			addr = get_arg_value(arg)
			if addr != 0:
#				addr_is_symbol(addr)
				display_rwsem_info(0, addr, 0, 0)
#				check_xfs_inode_locks(addr)

#	else:
#		check_pids()




# vim: sw=4 ts=4 noexpandtab
