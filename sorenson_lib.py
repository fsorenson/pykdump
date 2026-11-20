#!/usr/bin/python
from __future__ import print_function
import argparse
import re
import string
import sys
import inspect
import time
import math

from pykdump.API import *
from LinuxDump.Tasks import TaskTable
from LinuxDump.fs.dcache import *
from functools import wraps, partial

DEFAULT_RLVL = 3
PAGE_SIZE = 4096

def obj_is_inttype(obj):
	return isinstance(obj, int)

def obj_is_floattype(obj):
	return isinstance(obj, float)

def flags_to_string(flags, strings):
	result = []
	for name, val in strings.items():
		if flags & (1 << val) != 0:
			result.append(name)
	return "|".join(result)

def defines_to_string(match_val, strings):
	for name, val in strings.items():
		if match_val == val:
			return name
	return "UNKNOWN"

def get_arg_value(arg):
	try:
		if '.' in arg:
			return float(arg)
		if arg.lower().startswith('0x'):
			return int(arg, 16)
		if arg.startswith('0') and all(c in string.octdigits for c in arg):
			return int(arg, 8)
		if all(c in '0123456789' for c in arg):
			return int(arg, 10)
		return int(arg, 16)
	except ValueError:
		return 0

def timespec_to_string(ts_in):
	ts = None
	try:
		if ts_in.PYT_symbol == "struct timespec" or ts_in.PYT_symbol == "struct timespec64":
			ts = ts_in.tv_sec + ts_in.tv_nsec / 1000000000.0
	except AttributeError:
		pass
	if obj_is_inttype(ts_in):
		ts = ts_in
	elif obj_is_floattype(ts_in):
		ts = ts_in
	if ts is None:
		return None
	try:
		lt = time.localtime(ts)
		return "{s}.{ss:09.0f} {tz}".format(s=time.strftime('%Y-%m-%d %H:%M:%S', lt), ss=(ts % 1) * 1000000000, tz=time.strftime('%Z', lt))
	except:
		return None

def indent_str(lvl):
	return "{spaces}".format(spaces = ' ' * 4 * lvl)

def indent(lvl):
	print(indent_str(lvl), end="")

def val_to_units_string(val, base, custom_strings=None):
	if custom_strings == None:
		if base == "SI":
			base = 1000
			unit_strings = [ "", "K", "M", "G", "T", "P", "E", "Z", "Y" ]
		elif base == 1000:
			unit_strings = [ " Bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB" ]
		elif base == 1024:
			unit_strings = [ " Bytes", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB" ]
		else:
			base = 1
	else:
		unit_strings = custom_strings

	if base == 1:
		return "{}".format(val)

	if val == 0:
		unit = unit_strings[0].strip()
		return "0 {}".format(unit) if unit else "0"

	negative = False
	if val < 0:
		negative = True
		vale = -val

	i = int(math.floor(math.log(val, base)))
	if i >= len(unit_strings):
		return "-{}".format(val) if negative else "{}".format(val)

	divider = math.pow(base, i)
	unit = unit_strings[i].strip()
	val_divided = val / divider
	val_str = "{:.0f}".format(val_divided) if (int(val_divided) == val_divided) else "{:.2f}".format(val_divided)
	res = "{} {}".format(val_str, unit) if unit else val_str
	return "-{}".format(res) if negative else res

def get_enum_info(enum_name):
	try:
		return EnumInfo("enum " + enum_name)
	except:
		return None

def get_enum_string(val, enum_name):
	str_val = "UNKNOWN"
	try:
		_S_enum_info = get_enum_info(enum_name)
		if _S_enum_info is None:
			return str_val
		try:
			_enum_key_list = sorted(_S_enum_info, key=lambda x: _S_enum_info[x])
			str_val = _enum_key_list[val]
		except: # no idea
			pass
	except:
		pass
	return str_val

def get_enum_bit_string(val, enum_name):
	str_val = "UNKNOWN"
	try:
		_S_enum_info = get_enum_info(enum_name)
		if _S_enum_info is None:
			return str_val
		try:
			_enum_key_list = sorted(_S_enum_info, key=lambda x: _S_enum_info[x])
			str = _enum_key_list[val.bit_length() - 1]
		except:
			pass
	except: # no idea
		pass
	return str_val

def print_enum_bit(val, enum_name):
	str = get_enum_bit_string(val, enum_name)
	print("{}".format(str))
	return str

def get_enum_tag_value(tag, enum_name):
	_S_enum_info = get_enum_info(enum_name)
	if _S_enum_info is None:
		return None
	try:
		_enum_key_list = sorted(_S_enum_info, key=lambda x: _S_enum_info[x])
		for k in _enum_key_list:
			if k == tag:
				return _S_enum_info[k]
	except:
		pass
	return None

def struct__member_obj(struct_obj, member):
	try:
		if struct_obj.hasField(member):
			member_obj = struct_obj.Eval(member)
			return member_obj
	except:
		pass
	return None

def struct__has_member(str, mbr):
	return (member_size("struct " + str, mbr) != -1)

def fmt_struct_addr(name, addr):
	return "(struct {name} *)0x{addr:016x}".format(name = name, addr = addr)

def qstr(addr):
	try:
		q = readSU("struct qstr", long(addr))
		len = q.len
		return readmem(q.name, q.len)
	except:
#		print("hmm. some exception")
		pass

def printDict(di, fmt="{:25s}: {}"):
	for (key, val) in di.items():
		print(fmt.format(str(key), val))

def list_entry(tmp_addr, struct, member):
	try:
		addr = container_of(tmp_addr, "struct " + struct, member)
		return readSU("struct " + struct, addr)
	except:
		return None

def call_foreach_args(func, args):
	for arg in args:
		addr = get_arg_value(arg)
		if addr != 0:
			func(addr)

# vim: sw=4 ts=4 noexpandtab
