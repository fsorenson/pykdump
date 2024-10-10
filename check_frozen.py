#!/usr/bin/python
import pprint
import argparse
import re
from pykdump.API import *
from LinuxDump.Tasks import TaskTable
from fs_lib import *

pp = pprint.PrettyPrinter(indent=4)

SPACER      = "    "
DEBUG       = " - DEBUG - "
superBlocks = {}
maxLen      = 0
_MAXDEPTH_  = 15


def get_time_ms_pretty_old(t):
	ns = int((t % 1000) * 1000000)
	s = int(t / 1000)
	m = int(s / 60)
	s %= 60
	h = int(m / 60)
	m %= 60
	d = int(h / 24)
	h %= 24
	return "%d %2d:%02d:%02d.%09d" % (d, h, m, s, ns)

def get_time_ms_pretty(t):
	return pp_time_ms(t)

def task_get_last_arrival_pretty(pid):
	tt = TaskTable()
#	pp.pprint(tt)
#	return
	if (pid > INT_MAX):
		t = readSU("struct task_struct", pid)
		if (not tt.getByTid(t.pid)):
			print("Bogus addr")
			return "? ??:??:??.?????????"
		t = Task(t, tt)
	else:
		t = tt.getByTid(pid)
	if (t):
#		lr = t.Last_ran
#		basems = tt.basems
#		basems = jiffies
		ran_ago = t.Ran_ago

#		delay = get_time_ms_pretty(basems - lr)
		delay = get_time_ms_pretty(ran_ago)
		return delay
	else:
		return "? ??:??:??.?????????"


def try_something():
	try:
		tt
	except NameError:
		print("not in scope")
	else:
		print("cmd_run_wait known")


# shamelessly stolen from skywalker
# needs to become a library function, or whatever it's called in python--
def taskWaitQ(entry):

	processWaitQ = container_of(entry, "wait_queue_t", "task_list")

	return readSU("struct task_struct", processWaitQ.private)

# another skywalker gem that needs to become useable
class get_per_cpu():
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

	def __repr__(self):
		retstr = "per-cpu:"
		for selectedcpu in self.cpu.keys():
			retstr = "%s\n%s%3s: %s" %(retstr, SPACER, selectedcpu, self.cpu[selectedcpu])
		return retstr



def task_last_run(task_addr):
	last_run = 0
	timestamp = 0

	task = readSU("struct task_struct", long(task_addr, 16))

	if (member_size("struct task_struct", "last_run") != -1):
		last_run = task.last_run
		timestamp = last_run
	elif (member_size("struct task_struct", "timestamp") != -1):
		timestamp = task.timestamp
	else:
		timestamp = task.sched_info.last_arrival
	return timestamp

class superBlock:
    def __init__(self, addr, inputName, args = None):
        super_block = None
        if args:
            if args.debug and args.debug > 2:
#                print("{}inputAddr: {}".format(DEBUG, str(inputAddr)))
                print("{}addr: {}".format(DEBUG, str(addr)))
                print("{}inputName: {}".format(DEBUG, inputName))

        self.inputName   = inputName
        super_block      = readSU("struct super_block", addr)
        self.super_block = super_block
        self.addr        = Addr(super_block)
        self.sb_type     = str(super_block.s_type.name)
        self.s_id        = str(super_block.s_id)
        self.can_freeze  = super_block.s_op.freeze_fs
        if self.can_freeze:
            if (member_size("struct super_block", "s_writers") != -1):
                self.frozen = super_block.s_writers.frozen
                self.unfreeze_waiters = super_block.s_writers
            else:
                self.frozen = super_block.s_frozen
                self.unfreeze_waiters = super_block.s_wait_unfrozen
        superBlocks[self.super_block] = self.inputName

parser = argparse.ArgumentParser(description='Display mounts and frozen filesystem status')
parser.add_argument('-d', '--debug', action="count", help='Debugging output. Add additional flags to increase verbosity.')
parser.add_argument('-q', '--quiet', action="store_true", help='Only show frozen filesystems')
args = parser.parse_args()

#percpu = get_per_cpu()

#pp.pprint(vars(percpu))

#try_something()


def get_dentry_name(dentry):
    namelen = dentry.d_name.len
    if (namelen):
        # PyKdump does not convert it to SmartString automatically
        # as it is unsigned, 'const unsigned char *name;'
        addr = int(dentry.d_name.name)
        return  SmartString(readmem(addr, namelen), addr, None)
    else:
        return ""

def get_path(dentry, superBlock = None):
    tempDent = dentry
    outputStr = []
    x = 0
    while tempDent != dentry.d_inode.i_sb.s_root:
        if x < _MAXDEPTH_:
            outputStr.insert(0, get_dentry_name(tempDent))
            x += 1
            tempDent = tempDent.d_parent
        else:
            break

    if superBlock:
        if superBlocks[superBlock] == "/":
            return superBlocks[superBlock] + string.join(outputStr, '/')
        else:
            return superBlocks[superBlock] + "/" + string.join(outputStr, '/')
    else:
        return '/' + string.join(outputStr, '/')

#if args.list_dirty:
if 1:
    jiffies = readSymbol("jiffies")
    Supers        = []

    super_blocks = readSymbol("super_blocks")
    sb_list = readSUListFromHead(super_blocks, "s_list", "struct super_block")

    for sb in sb_list:
        if sb.s_op.freeze_fs: # freezable
            mount_list = []

            raw_list = readListByHead(sb.s_mounts)
            for le in raw_list:
                m = readSU("struct mount", container_of(le, "struct mount", "mnt_instance"))
                mount_list.append(m)
            for mount in mount_list:
#                mnt_src = mount.mnt.mnt_devname
                mnt_src = mount.mnt_devname
#                pathname = get_pathname(dentry, mount.mnt)
#                pathname = get_pathname(mount.mnt_mountpoint, mnt_src)
                pathname = get_pathname(mount.mnt_mountpoint, mount.mnt)
                print(" - (struct mount *)0x{:016x} - (struct vfsmount *)0x{:016x} - flags: 0x{:04x} - {}".format(
                    mount, mount.mnt, mount.mnt.mnt_flags, pathname))

                temp_sb = superBlock(sb, pathname)
                temp_sb.vfsmount = mount.mnt
                temp_sb.mount_source = mnt_src # devname
                temp_sb.mount_target = pathname
                Supers.append(temp_sb)

                superBlocks[temp_sb.super_block] = temp_sb.inputName

    if args.debug and args.debug > 2:
        print("")

    if args.debug:
        print("{}".format(DEBUG))
        pp.pprint(Supers)
        print("{}\n\n".format(DEBUG))

    if args.debug and args.debug > 3:
        print("{}After".format(DEBUG))
        for BDI in Supers:
            pp.pprint(vars(BDI))
            print("")
        print("{}\n".format(DEBUG))

    for superBlock in Supers:
        if not superBlock.can_freeze:
            continue

        if superBlock.frozen:
            print("Warning: found frozen {} super_block: {:016x} - super_block.s_frozen = {} - on device {} ({}) mounted at {}".format(
                superBlock.sb_type, superBlock.addr, superBlock.frozen, superBlock.mount_source, superBlock.s_id, superBlock.mount_target))

#		temp_task_list = readListByHead(superBlock.super_block.s_writers.wait_unfrozen.task_list)
            try:
                temp_task_list = readListByHead(superBlock.unfreeze_waiters.wait_unfrozen.task_list)
            except:
                temp_task_list = readListByHead(superBlock.unfreeze_waiters.wait_unfrozen.head)
            if len(temp_task_list):
                print("{}PID {}".format("Blocked".ljust(22), "PID".rjust(8), "COMM".ljust(25)))
                for entry in temp_task_list:
                    delay = task_get_last_arrival_pretty(taskWaitQ(entry).pid)
                    print("[{}] {}  {}".format(delay, str(taskWaitQ(entry).pid).rjust(8), str(taskWaitQ(entry).comm.strip(" ")).ljust(25)))
#                    task_get_last_arrival(taskWaitQ(entry).pid)
#                    print "PID: " + str(taskWaitQ(entry).pid)
#                    print "COMM: " + str(taskWaitQ(entry).comm.strip(" "))
        else:
            if not args.quiet:
                print("not frozen: {} super_block: {:016x} - super_block.s_frozen = {} - on device {} ({}) mounted at {}".format(
                    superBlock.sb_type, superBlock.addr, str(superBlock.frozen), superBlock.mount_source, superBlock.s_id, superBlock.mount_target))
