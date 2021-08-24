#!/usr/bin/python
from __future__ import print_function
import argparse
import re
import string
import sys
from pykdump.API import *
from LinuxDump.Tasks import TaskTable
from obj_info import info
from LinuxDump.fs.dcache import *
from functools import wraps, partial

#import ppstruct_vars
ppstruct_vars = {}

# since I'm still clueless with python...
pp_import_strings = [ "", "struct_", "fs.", "fs.struct_", "ppstruct_types." ]

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
	return pp_time_ns(us * 1000)

def pp_time_ms(ms):
	return pp_time_ns(ms * 1000 * 1000)

def pp_time_s(s):
	return pp_time_ns(s * 1000 * 1000 * 1000)

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

#	print("unit strings: {}".format(unit_strings))

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

def pp_enum_string(val, enum_name):
	str = get_enum_string(val, enum_name)
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

def pp_uid(addr):
	try:
		sym = addr.PYT_symbol
	except:
		return ".uid = {uid}".format(uid=addr)

	if sym == 'kuid_t':
		return ".uid = {uid}".format(uid=addr.val)
	else:
		return ".uid = {uid}".format(uid=addr)
def pp_gid(addr):
	try:
		sym = addr.PYT_symbol
	except:
		return ".gid = {gid}".format(gid=addr)

	if sym == 'kgid_t':
		return ".gid = {gid}".format(gid=addr.val)
	else:
		return ".gid = {gid}".format(gid=addr)

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

# lost where this was going... come back to it later, and see if I can remember
#def struct__member_obj(struct_obj, member):
#	try:
#		member_addr = struct__member_addr(struct_obj, member)
#
#		member_obj = addr_struct_obj(
#
#member_obj = struct__member_obj(addr, member_name)
#if member_obj == None:
#return
#
#	member_addr = long(member_obj)
#try:
#	sym = member_obj.PYT_symbol
#except AttributeError:
#	if type(member_obj) == type(0) or type(member_obj) == type(0L):
#		print("{ind}.{mbr} - {obj}".format(ind=indent_str(ilvl), mbr=member_name, obj=member_obj))
#		return
#	else: # no PYT_symbol...  now what?
#		print("not sure what '{sym}.{mbr}' type '{type}' is".format(sym=addr.PYT_symbol[7:], mbr=member_name, type=type(member_obj)))
#		return
#if sym.startswith('struct '):
#	member_type = sym[7:]




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


def pp_member_val(struct_obj, member_name):
	ret = ""
	member_obj = struct__member_addr(obj, member_name)
	if member_obj is None:
		return ""

	member_addr = long(member_obj)

	if member_obj == "long":
		return ".{name} = {val}".format(name=member_name, val=long(member_obj))

	try:
		sym = member_obj.PYT_symbol
	except:
		return " * %s *" % ret, member_obj.PYT_symbol
		return ""

	if sym == "kgid_t":
		ret = "kgid_t::: "
		return "ret:%s .%s = %d" % ret, member_name, struct_obj.val.gid_t
#			return ".%s = %d" % member_name, member_obj.val.gid_t
	if sym == "kuid_t":
		return "%s .%s = %d" % ret, member_name, member_obj.val.uid_t
	return "{ret}.{name} = {addr}".format(ret=ret, name=member_name, addr=long(member_obj))

# returns the pp_struct function, or False
def ppstruct_get_pp_struct_func(struct_type):
	pp_func_name = "pp_struct_{}".format(struct_type)
	known = globals().copy()
	known.update(locals())
#	print("**trying to find function {}".format(pp_func_name))

	method = known.get(pp_func_name)
	if method:
		print("found known method to print {}".format(pp_func_name))
		return method
#	printDict(known)

#	print("looking for method to print {}".format(pp_func_name))

	if 1:
		try:
			import importlib
		except Exception as err:
			print("Unable to import importlib: {}".format(err))
			return False



#	for str in ppstruct_vars.pp_import_strings:




	for str in pp_import_strings:
		imp = "{}{}".format(str, struct_type)
		try:
#			print("trying to import {}".format(imp))
			mod = importlib.import_module(imp)
		except Exception as e:
#			print("Exception trying to import {}: {}".format(imp, 3))
			pass
			continue
		method = mod.__dict__[pp_func_name]
		if method:
			return method
	return False

def ppstruct_func_exists(struct_type):
	return ppstruct_get_pp_struct_func(struct_type)


class goober_ppstruct_vars():
	def __init__(self):
		self.pp_struct_opts = {}
		self.pp_struct_opts['counts'] = 0
		self.pp_struct_opts['recurse'] = 1
		self.pp_struct_opts['locks'] = 0
		self.pp_struct_opts['stats'] = 0
		self.pp_struct_opts['prune'] = 1

		self.pp_struct_prune = {}
		self.pp_struct_prune['list'] = {}
		self.pp_import_strings = [ "", "struct_", "fs.", "fs.struct_", "ppstruct_types." ]

def init_ppstruct_vars():
	global ppstruct_vars

	ppstruct_vars = {}
	ppstruct_vars['pp_struct_opts'] = {}
	ppstruct_vars['pp_struct_opts']['counts'] = 0
	ppstruct_vars['pp_struct_opts']['recurse'] = 1
	ppstruct_vars['pp_struct_opts']['locks'] = 0
	ppstruct_vars['pp_struct_opts']['stats'] = 0
	ppstruct_vars['pp_struct_opts']['prune'] = 1
#	ppstruct_vars['pp_struct_opts'][''] =

	ppstruct_vars['pp_struct_prune'] = {}
	ppstruct_vars['pp_struct_prune']['list'] = {}
	ppstruct_vars['pp_import_strings'] = [ "", "struct_", "fs.", "fs.struct_" ]

#	ppstruct_vars = ppstruct_vars()



def pp_struct(type, addr, rlvl=1, ilvl=0):
	if not 'ppstruct' in globals():
		init_ppstruct_vars()

	func = ppstruct_get_pp_struct_func(type)

	if not func == False:
		func(addr, rlvl=rlvl, ilvl=ilvl)
	else:
		print("{} - not implemented".format(fmt_struct_addr(type, addr)))

def pp_struct_old3(type, addr, rlvl=1, ilvl=0):
	pp_func_name = "pp_struct_%s" % type

	known = globals().copy()
	known.update(locals())
	method = known.get(pp_func_name)
	if method:
		try:
			method(addr, rlvl=rlvl, ilvl=ilvl)
			return
		except:
			print("Could not call '{}'".format(pp_func_name))
	try:
		import importlib
	except:
		print("Error: could not import importlib")
		return

	mod = None
	for str in pp_import_strings:
		imp = "{}{}".format(str, type)

		try:
			mod = importlib.import_module(imp)
		except:
			continue
		method = mod.__dict__[pp_func_name]
		if method:
				method(addr, rlvl=rlvl, ilvl=ilvl)
				return

	print("{} - not implemented".format(fmt_struct_addr(type, addr)))



def pp_struct_old2(type, addr, rlvl=1, ilvl=0):
	try:
		import importlib
	except:
		print("Error: could not import importlib")
		return

	mod = None
	pp_func_name = "pp_struct_%s" % type
	for str in pp_import_strings:
		imp = "{}{}".format(str, type)

		try:
			mod = importlib.import_module(imp)
			break
		except:
			continue
		method = mod.__dict__[pp_func_name]
		if method:
			try:
				method(addr, rlvl=rlvl, ilvl=ilvl)
				return
			except:
				print("Could not call '{}' from '{}'".format(pp_func_name, imp))
#		else:
#			print "
	print("{} - not implemented".format(fmt_struct_addr(type, addr)))


def pp_struct_member_format_simple(struct_obj, member_name):
	try:
		return ".{} = {}".format(member_name, struct_obj.Eval(member_name))
	except:
		return ".{} = <NONE>"


def pp_struct_member_type(struct_obj, member_name, member_type, rlvl=1, ilvl=0):
	member_obj = struct__member_obj(struct_obj, member_name)
	if member_obj != None:
		member_addr = long(member_obj)

		print("{ind}.{mbr} -".format(indent_str(ilvl), mbr=member_name), end="")
		pp_struct(member_type, member_addr, rlvl=rlvl, ilvl=ilvl)

def pp_struct_member(addr, member_name, rlvl=1, ilvl=0):
	member_obj = struct__member_obj(addr, member_name)
	if member_obj == None:
		return

	member_addr = long(member_obj)
	try:
		sym = member_obj.PYT_symbol
	except AttributeError:
#		if type(member_obj) == type(0) or type(member_obj) == type(0L):
		if type(member_obj) == type(0):
			print("{ind}.{mbr} - {obj}".format(ind=indent_str(ilvl), mbr=member_name, obj=member_obj))
			return
		else: # no PYT_symbol...  now what?
			print(" not sure what '{str}.{mbr}' type '{typ}' is".format(str=addr.PYT_symbol[7:], mbr=member_name, typ=type(member_obj)))
			return
	if sym.startswith('struct '):
		member_type = sym[7:]
	else:
		print("not sure how to display '{str}.{mbr}' type '{typ}'".format(addr.PYT_symbol[7:], member_name, type(member_obj)))
		return

	print("{ind}.{mbr}".format(ind=indent_str(ilvl), mbr=member_name), end="")
	pp_struct(member_type, member_addr, rlvl, ilvl)


def qstr(addr):
	try:
		q = readSU("struct qstr", long(addr))
		len = q.len
		return readmem(q.name, q.len)
	except:
#		print("hmm. some exception")
		pass


def struct_printer_ORIG(struct_name):
	def decorator(func):
		@wraps(func)
		def wrapper(addr, rlvl=1, ilvl=0):
			struct_name = func.__name__[10:]

			print("{}".format(fmt_struct_addr(struct_name, addr)))

			if addr != 0 and rlvl > 0:
				obj = addr_struct_obj(struct_name, addr)
				if obj != None:
					func(obj, rlvl-1, ilvl+1)
		return wrapper
	return decorator

def struct_label_string_quiet_fail(func):
	def print_label_quiet_fail(*args, **kwargs):
		func(*args, label_quiet_fail=True, **kwargs)
	return print_label_quiet_fail

def struct_label_string(label_field):
	def struct_label_decorator(func):
		@wraps(func)
		def wrapper(*args, **kwargs):
			struct_label_field = label_field
			func(*args, struct_label_field=label_field, **kwargs)
		return wrapper
	return struct_label_decorator

def print_oneline(func):
	def print_oneline_wrapper(*args, **kwargs):
		func(*args, print_oneline=True, **kwargs)
	return print_oneline_wrapper

def print_no_NL(func):
#	def decorator(func):
#		@wraps(func)
		def print_no_NL_wrapper(*args, **kwargs):
			func(*args, no_nl=True, **kwargs)
		return print_no_NL_wrapper
#	return decorator

def never_prune(func):
	def never_prune_wrapper(*args, **kwargs):
		func(*args, never_prune=True, **kwargs)
	return never_prune_wrapper

def requires_rlvl(func, req):
	def requires_rlvl_decorator(func):
		@wraps
		def wrapper(*args, **kwargs):
			func(*args, requires_rlvl=req, **kwargs)
		return wrapper
	return requires_rlvl_decorator
def no_rlvl(func):
	def wrapper(*args, **kwargs):
		func(*args, requires_rlvl=0, **kwargs)
	return wrapper
def nonrecursive(func):
	def nonrecursive_wrapper(*args, **kwargs):
		func(*args, requires_rlvl=0, **kwargs)
	return nonrecursive_wrapper

def struct_printer(func):
	def struct_printer_decorator(addr, rlvl=1, ilvl=0, \
			struct_label_field=None, label_quiet_fail=True, no_nl=False, print_oneline=False, never_prune=False, requires_rlvl=1):
		struct_name = func.__name__[10:]
		prune_this = False

		if addr:
			obj = addr_struct_obj(struct_name, addr)

			prune_key = "{}.0x{:016x}".format(struct_name, addr)

			if not 'ppstruct_vars' in globals():
				global ppstruct_vars

				try:
					print("attempting to load ppstruct_vars")
					init_ppstruct_vars()
				except:
					pass

#			if not ppstruct_vars:   ##### FIXME - this is still not working for pp_struct() called outside the ppstruct command
#				ppstruct_vars.pp_struct_prune = {}
#				ppstruct_vars.pp_struct_prune['list'] = {}

				print("Setting the ppstruct_vars")
			if ppstruct_vars['pp_struct_opts']['prune'] and not never_prune:
				try:
					prune_previous_rlvl = ppstruct_vars['pp_struct_prune']['list'][prune_key]
				except:
					prune_previous_rlvl = -1
					pass


			prune_this = True if (not never_prune) and \
					ppstruct_vars['pp_struct_opts']['prune'] and \
					(rlvl <= prune_previous_rlvl) else False
			if not never_prune:
				ppstruct_vars['pp_struct_prune']['list'][prune_key] = max(rlvl, prune_previous_rlvl)
		else: obj = None

		print("{}".format(fmt_struct_addr(struct_name, addr)), end="")

		if struct_label_field != None and obj != None:
			try:
				label = obj.Eval(struct_label_field)
				ot = obj__type(label)
				if ot == 'struct' and obj__struct_type(label) == 'qstr':
					label = qstr(label).decode("utf-8")
#				elif ot == 'class' and obj__class_type(label) == "'pykdump.wrapcrash.SmartString'":
					# perfect...  nothing to do
				print(" - '{label}'".format(label=label), end="")
			except:
				if not label_quiet_fail:
					print(" - '{label} unknown'".format(label=struct_label_field), end="")
				pass
		if no_nl == False and print_oneline == False:
			print()

		if (obj != None) and (long(obj) != 0) and (rlvl - requires_rlvl >= 0) and (not prune_this):
			try:
				func(obj, rlvl=rlvl-requires_rlvl, ilvl=ilvl+1)
			except Exception as err:
				print("Exception occurred while printing {}: {}".format(struct_name, str(err)))
				print("{}, func.name='{}'".format(str(func), func.__name__))
#				print("struct label 
				pass
	return struct_printer_decorator


def call_foreach_argv(func):
	for arg in sys.argv:
		addr = get_arg_value(arg)
		if addr != 0:
			func(addr, rlvl=DEFAULT_RLVL)

def program_display_struct(struct_func):
	call_foreach_argv(struct_func)


def printDict(di, fmt="{:25s}: {}"):
	for (key, val) in di.items():
		print(fmt.format(str(key), val))

def list_entry(tmp_addr, struct, member):
	try:
		addr = container_of(tmp_addr, "struct " + struct, member)
		return readSU("struct " + struct, addr)
	except:
		return None

##### probably need these to be at the bottom, after everything is defined
#import *
from misc import *
from fs import *
from net import *

# vim: sw=4 ts=4 noexpandtab
