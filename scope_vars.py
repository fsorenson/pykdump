#!/usr/bin/python

from __future__ import print_function

from fs_lib import *
import re
from pykdump.API import *


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

	m = re.match("^([a-zA-Z_][0-9a-zA-Z_]*)(|\+((0x)?[0-9a-zA-Z]+))$", fn_str)
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

def func_string(fname):
	vi = whatis(fname)
	out = []
	for ati in vi.ti.prototype:
		astype, apref, asuff = ati.fullname()
		out.append("{} {}{}".format(astype, apref, asuff).strip())
	return "{} {}({})".format(out[0], fname, ", ".join(out[1:]))

#m = re.match("^  \[([0-9a-f]{16})\]$", line)
#if m:
#addr = int(m.group(1), 16)

def decode_complex(complex_expr):
	print("how do we decode this?\n{}".format(complex_expr))


def get_text_addr_vars(func, text_addr):
	print("")
	print("checking symbols in scope at 0x{:016x} in '{}'".format(text_addr, func))
	print("")

	r = exec_crash_command("gdb info scope *0x{:016x}".format(text_addr))




	cur_sym = ""
	loc_strings = []
	sym_size = 0
	multi_loc = 0
	sym_in_scope = 0
	parsing_complex = 0
	is_func = 0

	m = re.match("^Scope for (\*0x[0-9a-fA-f]+):$[\n\r]+(.+)$", r, flags=re.MULTILINE + re.DOTALL)
	if not m:
		print("Unable to match scope")
		return 0
	if m.group(1) != "*0x{:016x}".format(text_addr):
		print("Unable to match desired scope '*0x{:016x}' with returned '{}'".format(text_addr, m.group(1)))
		return 0

	print("something matched: {}".format(m))

	sym_text = m.group(2)

	sym_re_str = "^Symbol ([a-zA-Z_][a-zA-Z0-9_]*) is "

	is_mult_loc_str = "(multi-location):$.+?^, length ([0-9]+)\.$"
	is_label_re_str = "a (label) at address 0x[0-9a-fA-F]+, length ([0-9]+)\.$"
	is_func_re_str = "a (function) at address 0x[0-9a-fA-F]+, length ([0-9]+)\.$"
#	is_func_re_str = "a (function).+?\.$"
	is_opt_out_str = "(optimized out)\.$"


	full_pattern = "(" + sym_re_str + "(" + \
		"{}".format(is_mult_loc_str) + "|" + \
		"{}".format(is_label_re_str) + "|" + \
		"{}".format(is_func_re_str) + "|" + \
		"{}".format(is_opt_out_str) + \
		")?)+"
#	"{})*".format(is_mult_loc_str)
	print("regex pattern is '{}'".format(full_pattern))
	rex = re.compile(full_pattern, re.MULTILINE | re.DOTALL)

#'(^Symbol ([a-zA-Z_][a-zA-Z0-9_]*) is ((multi-location):$.+?^, length [0-9]+\.$|a (label) at address 0x[0-9a-fA-F]+, length [0-9]+\.$))*?'
#(^Symbol ([a-zA-Z_][a-zA-Z0-9_]*) is ((multi-location):$.+?^, length [0-9]+\.$|a (label) at address 0x[0-9a-fA-F]+, length [0-9]+\.$|is (optimized out)))+


#	m = re.match("^Symbol ([a-zA-Z_][a-zA-Z0-9_]*) is (" + "{})", sym_text, flags=re.MULTILINE + re.DOTALL)
#	m = re.match(full_pattern, sym_text, flags=re.MULTILINE + re.DOTALL)

	for match in rex.finditer(sym_text):
#		cur_sym, part2, part3 = match.groups()
#		cur_sym = cur_sym.strip()

#		print("Symbol: {}".format(cur_sym))
#		print("{}".format(match.groups()))

		print("match: symbol {}".format(match.group(2)))
#		print("\t1) {}".format(match.group(1)))
		for i in xrange(1,12):
			try:
				print("\t{}) {}".format(i, match.group(i)))
			except:
				pass

		symbol = match.group(2)


		if match.group(4) is "multi-location":
			print("multilocation thingy")
#		elif match.group(10) is not None:
#			print("{}:\n\toptimized out")



#	if m:
#		print("got a match: {}".format(m.groups(1)))
#		print("2 {}".format(m.group(2)))
#		print("3 {}".format(m.group(3)))

		print("")
		continue


	print("***************************")

	return

	for l in r.strip().split("\n"):
		f = l.strip().split(" ")
		if f[0] == "Scope":
			if f[2] != "*0x{:016x}:".format(text_addr):
#			if f[2] != "{}:".format(func):
				print("Hmm... supposed to be scope for '*0x{:016x}', but this says '{}'".format(text_addr, f[2]))
#				print("Hmm... supposed to be scope for '{}', but this says '{}'".format(func, f[2]))
		elif f[0] == "Symbol":
			cur_sym = f[1]
			multi_loc = 0
			is_func = 0
			# Symbol ret__ is multi-location:
			if f[3] == "multi-location:":
				multi_loc = 1
			# Symbol get_current is a function at address 0xffffffff811ab249, length 1.
			elif "{} {} {}".format(f[2], f[3], f[4]) == "is a function":
#			f[4] == "function":
				m = re.match("^(0x[0-9a-fA-F]+),$", f[7])
				is_func = 1
				if m:
					func_call_addr = get_arg_value(m.group(1))
					print("{}:\n\tfunction at 0x{:016x}".format(cur_sym, func_call_addr))

					print("\t\t{}".format(func_string(addr_func(func_call_addr))))
#					fn_tmp = addr_func(func_call_addr)
#					print("\t\tfn_tmp = {}".format(fn_tmp))
#					vi = whatis(fn_tmp)
#					vi = whatis(fn_tmp)

#					out = []
#					for ati in vi.ti.prototype:
#						astype, apref, asuff = ati.fullname()
#						out.append(("%s %s%s" % (astype, apref, asuff)).strip())

#					print("{} {}({});".format(out[0], fn_tmp, ", ".join(out[1:])))


#					print("\t\t{}".format(whatis(addr2sym(func_call_addr))))

					cur_sym = ""
				else:
					print("\tcouldn't find function address in '{}'".format(f[7]))
			# Symbol save is optimized out.
			elif "{} {} {}".format(f[2], f[3], f[4]) == "is optimized out.":
				print("{}:\n\toptimized out".format(cur_sym))
				cur_sym = ""
			# Symbol save is a complex DWARF expression:
			#      0: DW_OP_fbreg -64
			# , length 16.
			elif "{} {} {} {} {}".format(f[2], f[3], f[4], f[5], f[6]) == "is a complex DWARF expression:":
				parsing_complex = 1
			else:
				print("Can't decode '{}'".format(l))


#			print("symbol: {}".format(cur_sym))
		elif f[0] == "Range":
			r = f[1]
			m = re.match("^(0x[0-9a-fA-F]+)-(0x[0-9a-fA-F]+):$", r)
			if m:
#				print("match: {}".format(m.group(0)))
				start = get_arg_value(m.group(1))
				end = get_arg_value(m.group(2))
#				print("\tstart: 0x{:016x}".format(start))
#				print("\tend:   0x{:016x}".format(end))
#				print("\t\t{}".format(l))

				if (text_addr >= start) and (text_addr <= end):
#					print("\tsymbol is in scope: '{}'".format(l))
				# now...  _where/what_ is it?
#					print("\t... where?  '{}'".format(l))
					m = re.match(".+: a variable in \$(.+)$", l)
					if m:
#						print("\tin register ${}".format(m.group(1)))
						loc_strings.append("variable in register ${}".format(m.group(1)))
					else:
						loc_strings.append("** {}".format(l))
#				else:
#					loc_strings.append("not in scope 0x{:016x}-0x{:016x}".format(start, end))

			else:
				print("couldn't match: {}".format(r))
		elif f[0] == ",":
			if f[1] != "length":
				print("uhhh... what's '{}'?".format(f[1]))
			else:
#				print("size: {}".format(f[2]))
				size = f[2].rstrip(".")
				print("{} (size {}):".format(cur_sym, size))
				if parsing_complex:
					print("\tcomplex calculation:")
					for ls in loc_strings:
						print("\t\t{}".format(ls))
#				elif len(loc_strings) > 1:
				elif len(loc_strings) > 0:
#					print("")
					for ls in loc_strings:
						print("\t{}".format(ls))
#				elif len(loc_strings) == 1:
#					print("{}".format(loc_strings[0]))
				else:
					print("\tnot in scope")
#					print("something... loc_strings='{}'".format(loc_strings))

				cur_sym = ""
				loc_strings = []
				parsing_complex = 0
		elif parsing_complex:
#			print("{}".format(l))
			loc_strings.append(l)
		else:
			print("couldn't match: first field '{}' in '{}'".format(f[0], f))
			print("\tstring: '{}'".format(l))


# eventually want to pass the pid so we can go the whole way
# for now, just get what's in scope
#def get_scope(pid, addr):
def get_scope(addr):

	func = addr_func(addr)
	if addr == 0xffffffff811a9a5f:
		prev_addr = 0xffffffff811a9a5a
	elif addr == 0xffffffff811ab29a:
		prev_addr = 0xffffffff811ab295
	elif addr == 0xffffffffa0cc00e9:
		prev_addr = 0xffffffffa0cc00e4
	else:
		prev_addr = previous_insn_addr(addr)
	if prev_addr is not 0:
		prev_func = addr_func(prev_addr)
		if func != prev_func:
			print("func at 0x{:016x} is '{}', but func at 0x{:016x} is '{}'"
				.format(prev_addr, prev_func, addr, func))
			return 0
		print("func: {}".format(prev_func))
#		vi = whatis(prev_func)
#		print("\twhatis: {}".format(vi))
#		print("\twhatis.shortstr: {}".format(vi.shortstr()))
#		print("\twhatis.ti: {}".format(vi.ti))

#		print("\twhatis.fullstr: {}".format(vi.fullstr())) # fails with 'VarInfo' has no 'offset'
#		tt = vi.ti.getTargetType() # fails with PyKdump/GDB error in gdb_typeinfo
#		print("\ttarget type; {}".format(tt))
#		ti.dump() # dies with error

#		ti = vi.ti
#		print("\ttype fullname: {}".format(ti.fullname()))
#		print("\ttype typestr: {}".format(ti.typestr()))
#		print("\ttype fullstr: {}".format(ti.fullstr()))
#		print("\twhatis ti.details: {}".format(vi.ti.details))
#		print("\targs: {}".format(funcargs(prev_func)))


		try:
			print("\tgdb_typeinfo: {}".format(crash.gdb_typeinfo(prev_func)))
		except:
			pass


		get_text_addr_vars(prev_func, prev_addr)
	else:
		print("previous addr to {:016x}: {}".format(addr, prev_addr))

#	for entry in exec_crash_command("sym {:016x}".format(addr)).split("\n"):



if __name__ == "__main__":
        try:
		get_scope(get_arg_value(sys.argv[1]))
	except crash.error as e:
		print("failed: '{}'".format(sys.argv))
		print("error: {}".format(e))


#	get_scope(48600, 0xffffffff811ab29a)


# vim: sw=4 ts=4 noexpandtab
