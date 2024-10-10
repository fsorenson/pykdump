#!/usr/bin/python

import sys, os

def try_addpath(path):
	if os.path.isdir(path):
		if path not in sys.path:
			sys.path.append(path)

if __name__ == "__main__":
	check_paths = []

	args = sys.argv[1:]

	if len(args):
		for newpath in args:
			try_addpath(newpath)
	else:
		try_addpath(os.path.dirname(os.path.realpath(sys.argv[0])))

# vim: sw=4 ts=4 noexpandtab
