#!/usr/bin/python

from __future__ import print_function

from LinuxDump import *
from LinuxDump.Tasks import *
from LinuxDump.Tasks import TASK_STATE, TaskTable
from LinuxDump.BTstack import exec_bt
from pykdump.API import *
from LinuxDump.KernLocks import (decode_mutex)
import argparse
import sorenson_lib

debug_script = False


def ind(i):
	return "{spaces}".format(spaces = ' ' * 4 * i)


#task_states = __get_states_from_array()

def enum_string(enum_name, val):
	str = "UNKNOWN"
	try:
		_S_enum_info = EnumInfo("enum " + enum_name)
		if _S_enum_info is None:
			return str
		_enum_key_list = sorted(_S_enum_info, key=lambda x: _S_enum_info[x])
		str = _enum_key_list[val]
	except Exception as ex:
		pass
	return str

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

# explanation from longman:
# write lock: 0xffffffff00000001
# if the wait list isn't empty, 0xffffffff00000000 will be added
#  to the counter, resulting in 0xfffffffe00000001

def rwsem_owner(rwsem):
	rwsem = readSU("struct rw_semaphore", rwsem)

	try:
		o = (rwsem.owner.counter & 0xffffffffffffffff) & ~0x3
		return readSU("struct task_struct", o)
	except Exception as e:
		pass
	try:
		return readSU("struct task_struct", rwsem.owner & ~0x3)
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

		if reader_owned(s):
			owner_str = ""
			if anonymously_owned(s):
				owner_str = "anonymous reader task - possibly:"

			if owner:
				t = tt.getByTid(owner.pid)
				if t:
					state = task_state_str(t.state)
					owner_str += "{} ({} - {:6d} - {})".format(owner, state, owner.pid, owner.comm)
				else:
					owner_str += "Invalid owner: 0x{:016x}".format(owner)
			else:
				owner_str += "reader-owned (no task ptr)"
		elif count == 0:
			owner_str = "unlocked?"
		elif owner:
			t = tt.getByTid(owner.pid)
			if t:
				state = task_state_str(t.state)
				owner_str = "Write owner {} ({} - {:6d} - {})".format(owner, state, owner.pid, owner.comm)
			else:
				owner_str = "Invalid owner: 0x{:016x}".format(owner)
		else:
			owner_str = "unknown: 0x{:016x}".format(owner)

		ucount = count & 0xffffffffffffffff
		if s.hasField("owner"):
			# Modern rw_semaphore (Linux 5.3+):
			#   bit 0 (0x1): RWSEM_WRITER_LOCKED
			#   bit 1 (0x2): RWSEM_FLAG_WAITERS
			#   bit 2 (0x4): RWSEM_FLAG_HANDOFF
			#   bits 8+:     reader count (RWSEM_READER_SHIFT = 8)
			wcount = 1 if (ucount & 0x1) else 0
			rcount = ucount >> 8
			cflags = []
			if ucount & 0x1:
				cflags.append("WRITER_LOCKED")
			if ucount & 0x2:
				cflags.append("WAITERS")
			if ucount & 0x4:
				cflags.append("HANDOFF")
			cflags_str = "|".join(cflags) if cflags else "UNLOCKED"
			print("{}:".format(s))
			print("{}{}, counter: 0x{:016x} ({})".format(ind(2), owner_str, ucount, cflags_str))
		else:
			print("{}:".format(s))
			print("{}{}, counter: 0x{:016x}".format(ind(2), owner_str, ucount))


	except Exception as ex:
		print("{}exception with '{}': {}".format(ind(2), err, ex))
		pass
		return

	wl = []
	try:
		if s.hasField("first_waiter"):
			fw = Addr(s.first_waiter)
			print("{}first_waiter: 0x{:016x}".format(ind(2), fw))
			if fw:
				for w in readList(fw, inchead=True):
					wl.append(readSU("struct rwsem_waiter", w))
		else:
			print("{}wait_list: {:016x} ?".format(ind(2), s.wait_list))
			if Addr(s.wait_list) and Addr(s.wait_list) != s.wait_list.next:
				wltemp = readList(Addr(s.wait_list.next))
				for w in wltemp:
					if w == s.wait_list:
						break
					wl.append(readSU("struct rwsem_waiter", w))
	except Exception as ex:
		print("error reading rwsem_waiter list: {}".format(ex))
		return

	tt = None
	if (len(wl)):
		tt = TaskTable()

	print("{}waitlist: {}, write: {}, read count: {}".format(ind(2), len(wl), wcount, rcount))

	if warning != "":
		print(warning)

	for w in wl:
		task = w.task
		pid = -1
		if task != 0 and task != 1:
			try:
				pid = task.pid
				comm = task.comm
				t = tt.getByTid(pid)
				state = task_state_abbr(t.state)
				lr = t.Last_ran
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

	rwsem = readSU("struct rw_semaphore", rwsem_addr)
	try:
		if wqh_addr:
			wqh = readSU("struct wake_q_head", wqh_addr)  ##### this is a wait_list, not a wake_q_head, isn't it? ***** FIXME
	except:
		wqh = False
		pass

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

	if len(args.rwsems) > 0:
		for arg in args.rwsems:
			addr = get_arg_value(arg)
			if addr != 0:
#				addr_is_symbol(addr)
				display_rwsem_info(0, addr, 0, 0)

# vim: sw=4 ts=4 noexpandtab
