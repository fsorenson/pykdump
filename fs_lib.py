#!/usr/bin/python
from __future__ import print_function
import argparse
import re
import string
import sys
import inspect

from pykdump.API import *
from LinuxDump.Tasks import TaskTable
from LinuxDump.fs.dcache import *
from functools import wraps, partial

DEFAULT_RLVL = 3
PAGE_SIZE = 4096

def obj_is_inttype(obj):
#	if type(obj) == type(0) or type(obj) == type(0L):
	if type(obj) == type(0):
		return 1
	try:
		if type(obj) == type(0):
			return 1
	except:
		pass
	return 0

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
#		if all(c in string.intdigits for c in arg): ### stupid python doesn't have string.intdigits?
		if all(c in '0123456789' for c in arg):
			return int(arg, 10)
		return int(arg, 16)
	except ValueError:
		return 0

def timespec_to_string(ts_in):
	ts = None
	try:
#		crash> timespec
#	struct timespec {
#	    __kernel_time_t tv_sec;
#	    long tv_nsec;

#	crash> timespec64
#	struct timespec64 {
#	    time64_t tv_sec;
#	    long tv_nsec;

#		print("ts_in is {}".format(ts_in.PYT_symbol))
		if ts_in.PYT_symbol == "struct timespec" or ts_in.PYT_symbol == "struct timespec64":
#			print("found a timespec")
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
		import time
#		import datetime
#		from datetime import timedelta, time, date
#		from datetime import *
	except:
		print("no datetime?")
	try:
		lt = time.localtime(ts)
		return "{s}.{ss:09.0f} {tz}".format(s=time.strftime('%Y-%m-%d %H:%M:%S', lt), ss=(ts % 1) * 1000000000, tz=time.strftime('%Z', lt))
#		dt = datetime.data.fromtimestamp(ts)
#		return dt.isoformat()
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

	import math

	i = int(math.floor(math.log(val, base)))
	divider = math.pow(base, i)
	fmt = "{:.0f} {}" if (int(val/divider) == val/divider) else "{:.2f} {}"

	if i >= len(unit_strings):
		i = 0
		divider = 1
		return "{}".format(val)

	return fmt.format(val/divider, unit_strings[i])

def get_enum_info(enum_name):
	try:
		_S_enum_info = EnumInfo("enum " + enum_name)
		return _S_enum_info
	except:
		return None

def get_enum_string(val, enum_name):
	str = "UNKNOWN"
	try:
		_S_enum_info = get_enum_info(enum_name)
		if _S_enum_info is None:
			return str
		try:
			_enum_key_list = sorted(_S_enum_info, key=lambda x: _S_enum_info[x])
			str = _enum_key_list[val]
		except: # no idea
			pass
	except:
		pass
	return str

def get_enum_bit_string(val, enum_name):
	str = "UNKNOWN"
	try:
		_S_enum_info = get_enum_info(enum_name)
		if _S_enum_info is None:
			return str
		try:
			_enum_key_list = sorted(_S_enum_info, key=lambda x: _S_enum_info[x])
			str = _enum_key_list[val.bit_length() - 1]
		except:
			pass
	except: # no idea
		pass
	return str

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
#			print("checking {} ({}) and {}".format(k, _S_enum_info[k], tag))
			if k == tag:
#				print("found that {} matches {}. returning {}".format(k, tag, _S_enum_info[k]))
				return _S_enum_info[k]
	except:
		print("exception in get_enum_tag_value")
		pass
	return None

# this func only half-baked
def obj__type(obj):
	try:
		sym = obj.PYT_symbol
	except AttributeError:
#		if type(obj) == type(0) or type(obj) == type(0L):
		if type(obj) == type(0):
			return 'int'
		else:
			return "type '{}' is unknown".format(type(obj))
	if sym.startswith('struct '):
		return 'struct'
	if sym.startswith('class '):
		return 'class'

def obj__struct_type(obj):
	try:
		sym = obj.PYT_symbol
		if sym.startswith('struct '):
			sym = sym[7:]
			return sym
	except AttributeError:
#		if type(obj) == type(0) or type(obj) == type(0L):
#			return None
		return None
	return None
def obj__class_type(obj):
	try:
		sym = obj.PYT_symbol
		if sym.startswith('class '):
			sym = sym[6:]
			return sym
	except AttributeError:
#		if type(obj) == type(0) or type(obj) == type(0L):
#			return None
		return None
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

def addr_struct_obj(struct_name, addr):
	obj = None
	try:
		obj = readSU("struct " + struct_name, addr)
	except:
		print(" - unknown type 'struct {struct_name}'".format(struct_name = struct_name))
	return obj


def fmt_struct_addr(name, addr):
	return "(struct {name} *)0x{addr:016x}".format(name = name, addr = addr)

def struct__member_addr(obj, member_name):
	if obj.HasField(member_name):
		return obj.Eval(member_name)
	return 0

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

# vim: sw=4 ts=4 noexpandtab
