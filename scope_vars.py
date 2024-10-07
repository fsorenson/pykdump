#!/usr/bin/python

import re
from pykdump.API import *
import argparse


def indent_string(text, num=1):
	spacer = "\t"*num

	return "\n".join(spacer + line for line in text.split("\n"))

def get_arg_value(arg):
	try:
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

def previous_insn_addr(addr):
	prev_addr = 0

	try:
		r = exec_crash_command("dis -r 0x{:016x}".format(addr))
	except crash.error as e:
		print("error with exec_crash_command: {}".format(e))
		return 0

	lines = r.strip().split("\n")
	if len(lines) == 1:
		return addr
	for l in lines:
#		print("parsing '{}'".format(l))
		fields = l.split(" ")
		a = get_arg_value(fields[0])
		if addr != a:
			prev_addr = a
		elif prev_addr != 0:
			return prev_addr
	return 0

def addr_func(addr):
	l = exec_crash_command("sym 0x{:016x}".format(addr)).split("\n")
	fn_str = l[0].split(" ")[2]

	print("called addr_func for '{}' - fn_str is '{}'".format(addr, fn_str))

	m = re.match("^([a-zA-Z_][0-9a-zA-Z_]*)(\.[^ ]+)?(|\+((0x)?[0-9a-zA-Z]+))$", fn_str)
#	__fscache_disable_cookie.cold.26+0x2a
#	... .constprop

	if m:
#		print("match: {}".format(m.group(0)))
#		print("\tfunc name: {}".format(m.group(1)))
#		print("\toffset: {}".format(m.group(2)))
		return m.group(1)
	else:
		try:
			print("couldn't match: {:016x}".format(addr))
			print("\tl = {}".format(l))
			print("\tfn_str = {}".format(fn_str))
			print("m = {}".format(m))
		except:
			pass
	return ""

def func_addr(func):
	# try getting the addr using 'p', so we can handle addresses such as 'path_walk+0x8'
	l = exec_crash_command("p &{}".format(func)).split("\n")

	if len(l) == 2:
		result = l[1]
	elif len(l) == 1:
		result = l[0]
	else:
		print("unable to find address for '{}'".format(func))
		return 0

	m = re.match("^(\$[0-9]+)? = {(?P<prototype>.+?)} (?P<addr>0x[0-9a-fA-F]+) <(?P<loc_str>[^>]+)>$", result)

	if m:
		addr = get_arg_value(m.groups('addr'))
		return addr
	return 0


def func_string(fname):
	print("trying to get function for address {}".format(fname))

	try:
		vi = whatis(fname)
#		print("vi is {}".format(vi))
#		return sys.exit()
	except Exception as e:
		print("unable to call whatis(\"{}\") - {}".format(fname, e))
		return "ERROR"
	out = []
	for ati in vi.ti.prototype:
		astype, apref, asuff = ati.fullname()
		out.append("{} {}{}".format(astype, apref, asuff).strip())
	return "{} {}({})".format(out[0], fname, ", ".join(out[1:]))


multiloc_re_str = r"(?P<is_multiloc>multi-location):(?P<multiloc_content>.+?)^, length (?P<multiloc_len>[0-9]+)\."
complex_re_str = r"a (?P<is_complex>complex DWARF expression):(?P<complex_content>.+?)^, length (?P<complex_len>[0-9]+)\."
label_re_str = r"a (?P<is_label>label) at address (?P<label_addr>0x[0-9a-fA-F]+), length (?P<label_len>[0-9]+)\."
function_re_str = r"a (?P<is_function>function) at address (?P<function_addr>0x[0-9a-fA-F]+), length (?P<function_len>[0-9]+)\."
optimized_re_str = r"(?P<is_optimized>optimized out)\."

scope_re_str = r"Symbol (?P<symbol_name>[a-zA-Z_][a-zA-Z0-9_]*) is (?P<content>" + \
	multiloc_re_str + r"|" + complex_re_str + r"|" + label_re_str + r"|" + \
	function_re_str + r"|" + optimized_re_str + r")"


multiloc_range_complex_re_str = r"(?P<is_complex>complex) DWARF expression:\n(?P<dwarf_expr>.+?)^$"
multiloc_register_re_str = r"(?P<in_register>variable) in (?P<register_name>\$.+?)$"

multiloc_range_re_str = "Range (?P<range_start>0x[0-9a-fA-F]+)-(?P<range_end>0x[0-9a-fA-F]+): a " + \
	r"(" + multiloc_range_complex_re_str + r"|" + multiloc_register_re_str + r")"


def decode_complex(complex_expr):
#	print("how do we decode this?\n{}".format(complex_expr))
	return indent_string(complex_expr)


def get_text_addr_vars(func, text_addr):
	indent_str = "\t"
	indent_str2 = "\t\t"
	print("")
	print("checking symbols in scope at 0x{:016x} in '{}'".format(text_addr, func))
	print("{}{}".format(indent_str, func_string(func)))
	print("")

	r = exec_crash_command("gdb info scope *0x{:016x}".format(text_addr))

	m = re.match("^Scope for (\*0x[0-9a-fA-f]+):$[\n\r]+(.+)$", r, flags=re.MULTILINE + re.DOTALL)
	if not m:
		print("{}Unable to match".format(indent_str2))
		return
	if m.group(1) != "*0x{:016x}".format(text_addr):
		print("{}Unable to match desired scope '*0x{:016x}' with returned '{}'".format(indent_str2, text_addr, m.group(1)))
		return

	sym_text = m.group(2)

	rex = re.compile(scope_re_str, re.MULTILINE | re.DOTALL)

	for match in rex.finditer(sym_text):
		current_sym = match.group('symbol_name')

		if match.group('is_multiloc'):
#			print("\tmultiloc symbol, len {}".format(match.group('multiloc_len')))
			locations = []
			multiloc_content = match.group('multiloc_content')

			for range_match in re.finditer(multiloc_range_re_str, multiloc_content, re.MULTILINE | re.DOTALL):
				range_start = get_arg_value(range_match.group('range_start'))
				range_end = get_arg_value(range_match.group('range_end'))

				if range_start <= text_addr and text_addr <= range_end:
					if range_match.group('in_register'):
#						print("\tin register {}".format(range_match.group('register_name')))
						locations.append("in register {}".format(range_match.group('register_name')))
					else:
						d = decode_complex(range_match.group('dwarf_expr'))
						locations.append(d)
			if len(locations) == 0:
				print("{}{} - len {}: not in scope".format(indent_str, current_sym, match.group('multiloc_len')))
			elif len(locations) == 1:
				print("{}{} - len {}: {}".format(indent_str, current_sym, match.group('multiloc_len'), locations[0]))
			else:
				print("{}{} - len {}:".format(indent_str, current_sym, match.group('multiloc_len')))
				for loc in locations:
					print("{}* {}".format(indent_str2, loc))

		elif match.group('is_complex'):
			d = decode_complex(match.group('complex_content'))
			print("{}{} - len {}: {}".format(indent_str, current_sym, match.group('complex_len'), d))
		elif match.group('is_label'):
			print("{}{} - len {}: label at {}".format(indent_str, current_sym, match.group('label_len'), match.group('label_addr')))
#			print("\tlabel at {} (len: {})".format(match.group('label_addr'), match.group('label_len')))
		elif match.group('is_function'):
			print("{}{} - len {}: function at {}".format(indent_str, current_sym, match.group('function_len'), match.group('function_addr')))
#			print("\tfunction at {} (len: {})".format(match.group('function_addr'), match.group('function_len')))
		elif match.group('is_optimized'):
			print("{}{}: optimized out".format(indent_str, current_sym))
		else:
			print("Why did this match then? {}".format(match.group('content')))


def print_full_func_info(func):
	try:
		print("\tgdb_typeinfo: {}".format(crash.gdb_typeinfo(prev_func)))
	except:
		pass
	vi = whatis(func)
	print("\twhatis: {}".format(vi))
	print("\twhatis.shortstr: {}".format(vi.shortstr()))
	print("\twhatis.ti: {}".format(vi.ti))

	print("\twhatis.fullstr: {}".format(vi.fullstr())) # fails with 'VarInfo' has no 'offset'
	tt = vi.ti.getTargetType() # fails with PyKdump/GDB error in gdb_typeinfo
	print("\ttarget type; {}".format(tt))
	ti.dump() # dies with error

	ti = vi.ti
	print("\ttype fullname: {}".format(ti.fullname()))
	print("\ttype typestr: {}".format(ti.typestr()))
	print("\ttype fullstr: {}".format(ti.fullstr()))
	print("\twhatis ti.details: {}".format(vi.ti.details))
	print("\targs: {}".format(funcargs(func)))


# eventually want to pass the pid so we can go the whole way
# for now, just get what's in scope
#def get_scope(pid, addr):
def get_scope(func, addr):
#	print("func: {}".format(func))
	get_text_addr_vars(func, addr)


# -p <pid>
# -r - address(es) given is a return address...get the scope for the previous instruction
#      currently the default


if __name__ == "__main__":
	try:
#		opts_parser = argparse.ArgumentParser(version='0.01')
		opts_parser = argparse.ArgumentParser()
		opts_parser.add_argument('addrs', metavar='N', type=str, nargs='+',
			help='addresses for which to display scope')
		opts_parser.add_argument('--return', '-r', dest='return_addr', default=False, action='store_true',
			help='the address(es) is a return address, so get scope of previous instrution')

		args = opts_parser.parse_args()

		if len(args.addrs) < 1:
			print("usage: scope_vars [--return | -r] <address> [<address> ... ]")
			sys.exit(1)

		for req_addr_str in args.addrs:
			req_addr = get_arg_value(req_addr_str)
			if req_addr == 0:
				# try again by using the string as a symbol name/formula
				req_addr = func_addr(req_addr_str)
				if req_addr == 0:
					print("Can't get scope for '{}'".format(req_addr_str))
					continue
			req_func = addr_func(req_addr)
			check_addr = req_addr
			if args.return_addr == True:
				print("getting previous instruction address")
				prev_addr = previous_insn_addr(req_addr)
				check_addr = prev_addr
				if prev_addr != 0:
					prev_func = addr_func(prev_addr)
					if req_func != prev_func:
						print("func at 0x{:016x} is '{}', but func at 0x{:016x} is '{}'".format(
							req_addr, req_func, prev_addr, prev_func))

						check_addr = 0
#				else:
#					print("Unable to determine address of previous instruction to 0x{:016x}".format(req_addr))
			if check_addr:
				get_scope(req_func, check_addr)

	except crash.error as e:
		print("failed: '{}'".format(sys.argv))
		print("error: {}".format(e))


#	get_scope(48600, 0xffffffff811ab29a)


# vim: sw=4 ts=4 noexpandtab
