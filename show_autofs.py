#!/usr/bin/python

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


def display_autofs_waitqueue(awq):
	awq = readSU("struct autofs_wait_queue", awq)

	print("{}(struct autofs_wait_queue *)0x{:016x} - {} token: {}".format(ind(2), awq, SmartString(awq.name.name), awq.wait_queue_token))
	try:
		t = tt.getByPid(awq.pid)
		state = task_state_abbr(getTaskState(t))
#		lr = t.Last_ran
		delay = get_time_ms_pretty(t.Ran_ago)
		print("{}{:7d}  {:16s} {st} {time}".format(ind(3), awq.pid, t.comm, st=state, time=delay))

	except:
		try:
			t = tt.getByTid(awq.tgid)
			state = task_state_abbr(getTaskState(t))
			delay = get_time_ms_pretty(t.Ran_ago)
			print("{}{:7d}  {:16s} {st} {time}".format(ind(3), awq.pid, t.comm, st=state, time=delay))
		except:
			print("{}{:7d}  {:16s}".format(ind(3), awq.tgid, "unknown"))
			pass
		pass

#	nxt = awq.next
#	if nxt:
#		display_autofs_waitqueue(nxt)

def display_autofs_info(ai):
	jiffies = readSymbol("jiffies")
	print("{}(struct autofs_info *)0x{:016x} - {}".format(ind(2), ai, get_pathname(ai.dentry, 0)))
	print("{}last used {}".format(ind(3), get_time_ms_pretty(jiffies - ai.last_used)))


def display_autofs_sbi(sbi):

	sbi = readSU("struct autofs_sb_info", sbi)
	print("{}(struct autofs_sb_info *)0x{:016x}".format(ind(1), sbi))
	wqs = []
	try:
		queues = readList(sbi.queues)
	except Exception as ex:
		print("error reading rwsem_waiter list: {}".format(ex))
		pass
		return

	active_list = readSUListFromHead(sbi.active_list, "active", "struct autofs_info")
	if len(active_list):
		print("{}active list: {}".format(ind(1), len(active_list)))
		for ai in active_list:
			display_autofs_info(ai)

	expiring_list = readSUListFromHead(sbi.expiring_list, "expiring", "struct autofs_info")
	if len(expiring_list):
		print("{}expiring list: {}".format(ind(1), len(active_list)))
		for ai in expiring_list:
			display_autofs_info(ai)

#	print("{} queues".format(len(queues)))
	q = []
	for awq in queues:
		wq = awq
		while wq != 0:
			wq = readSU("struct autofs_wait_queue", wq)
			q.append(wq)
			wq = wq.next
#	print("qlen: {}".format(len(q)))
	if len(q):
		print("{}autofs_wait_queue: {}".format(ind(1), len(q)))
		for awq in q:
			display_autofs_waitqueue(awq)


#####
if __name__ == "__main__":
	tt = TaskTable()
	opts_parser = argparse.ArgumentParser()
#	opts_parser.add_argument('sbis', metavar='N', type=str, nargs='*',
#			help='autofs_wait_queue addresses to display')
#	opts_parser.add_argument('rwsems', metavar='N', type=str, nargs='*',
#			help='rwsemaphore addresses to display')
#	opts_parser.add_argument('--rwsems', dest='rwsems', default=[], metavar='N', type=str, nargs='*',
#			help='rwsem addresses to display')
	opts_parser.add_argument('--debug', '-d', dest='debug', default=[], action='store_true',
			help='show script debugging information')

	args = opts_parser.parse_args()
	if args.debug:
		debug_script = True

	super_blocks = readSymbol("super_blocks")
	sb_list = readSUListFromHead(super_blocks, "s_list", "struct super_block")
	autofs_sbs = []
	for sb in sb_list:
		s_type = sb.s_type.name
		if s_type == "autofs":
			autofs_sbs.append(sb)

	for autofs_sb in autofs_sbs:
		print("(struct super_block *)0x{:016x} - {}".format(autofs_sb, get_pathname(autofs_sb.s_root, 0)))
		sbi = readSU("struct autofs_sb_info", autofs_sb.s_fs_info)
		display_autofs_sbi(sbi)


# vim: sw=4 ts=4 noexpandtab
