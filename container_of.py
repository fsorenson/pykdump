#!/usr/bin/python

import sys, os

if __name__ == "__main__":
	mypath = os.path.dirname(os.path.realpath(sys.argv[0]))
	check_paths = [mypath, "/cores/crashext/epython/"]
	for p in check_paths:
		if os.path.isdir(p):
			if p not in sys.path:
				sys.path.append(p)

from fs_lib import *

def usage():
	print("usage: container_of <address> <struct_name> <member>")

if __name__ == "__main__":
	argc = len(sys.argv)

	if argc != 4:
		usage()
	else:
		try:
			addr = get_arg_value(sys.argv[1])
#			print("address is 0x{a:016x}, object type is {o}, member is {m}".format(a=addr, o=sys.argv[2], m=sys.argv[3]))
			container_addr = container_of(addr, "struct " + sys.argv[2], sys.argv[3])
			print("0x{:016x}".format(container_addr))
		except Exception as err:
			print("Error occurrred: {}".format(str(err)))
			usage()

# vim: sw=4 ts=4 noexpandtab
