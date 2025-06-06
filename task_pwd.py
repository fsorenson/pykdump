#!/usr/bin/env python
import sys, os
from LinuxDump import *
from LinuxDump.Tasks import *
from LinuxDump.Tasks import TaskTable


if __name__ == "__main__":
        mypath = os.path.dirname(os.path.realpath(sys.argv[0]))
        if mypath not in sys.path:
                sys.path.append(mypath)

def get_arg_value(arg):
    try:
        if '.' in arg: return float(arg)
        if arg.lower().startswith('0x'): return int(arg, 16)
        if arg.startswith('0') and all(c in string.octdigits for c in arg): return int(arg, 8)
#               if all(c in string.intdigits for c in arg): ### stupid python doesn't have string.intdigits?
        if all(c in '0123456789' for c in arg): return int(arg, 10)
        return int(arg, 16)
    except ValueError:
        return 0

        comm = task.comm
        state = task_state_abbr(t.state)

def task_show_pwd(task):

    task = readSU("struct task_struct", task)

    comm = task.comm
    fs = task.fs
    pwd = fs.pwd

    pwd_path = get_pathname(pwd.dentry, pwd.mnt)
    comm = task.comm
    pid = task.pid
    print("task: 0x{:016x}  pid: {:8d}  comm: {}   pwd: {}".format(
        Addr(task), pid, comm, pwd_path))

def pid_show_pwd(pid):
    tt = TaskTable()
    task = tt.getByTid(pid)

    if task == None:
        print("could not find task for pid {}".format(pid))
        return

    task_show_pwd(task.ts)

if __name__ == "__main__":
    exe_name = os.path.basename(sys.argv[0])
    if exe_name == "pid_pwd.py":
        if len(sys.argv) > 1:
            for arg in sys.argv[1:]:
                pid = get_arg_value(arg)
                pid_show_pwd(pid)
        else:
            print("usage: {} <pid> [<pid> ...]".format(sys.argv[0]))
    elif exe_name == "task_pwd.py":
        if len(sys.argv) > 1:
            for arg in sys.argv[1:]:
                task = get_arg_value(arg)
                try:
                    task_show_pwd(task)
                except:
                    pass
        else:
            print("usage: {} <task> [<task> ...]".format(sys.argv[0]))


# vim: sw=4 ts=4
