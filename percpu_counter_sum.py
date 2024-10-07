#!/usr/bin/python

from fs_lib import *
from LinuxDump.percpu import *

def usage():
	print("usage: percpu_counter_sum <address>")

if __name__ == "__main__":
	argc = len(sys.argv)

	if argc != 2:
		usage()
	else:
		try:
			ctr = readSU("struct percpu_counter", get_arg_value(sys.argv[1]))
			ret = percpu_counter_sum(ctr)
			print("0x{:016x}".format(ret))
		except Exception, err:
			print("Error occurrred: {}".format(str(err)))
			usage()

# vim: sw=4 ts=4 noexpandtab
