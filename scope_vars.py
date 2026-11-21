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

	m = re.match(r"^([a-zA-Z_][0-9a-zA-Z_]*)(\.[^ ]+)?(|\+((0x)?[0-9a-zA-Z]+))$", fn_str)
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

	m = re.match(r"^(\$[0-9]+)? = {(?P<prototype>.+?)} (?P<addr>0x[0-9a-fA-F]+) <(?P<loc_str>[^>]+)>$", result)

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


def format_reg_offset(base, offset):
	if offset == 0:
		return base
	if offset > 0:
		return "{} + {}".format(base, offset)
	return "{} - {}".format(base, -offset)


def eval_dwarf_expr(complex_expr, regs=None, read_mem=None):
	lines = [l for l in complex_expr.splitlines() if l.strip()]
	if not lines:
		return ""

	stack = []
	is_value = False
	pieces = []

	binops = {
		"DW_OP_and": "&",
		"DW_OP_or": "|",
		"DW_OP_xor": "^",
		"DW_OP_plus": "+",
		"DW_OP_minus": "-",
		"DW_OP_mul": "*",
		"DW_OP_div": "/",
		"DW_OP_mod": "%",
		"DW_OP_shl": "<<",
		"DW_OP_shr": ">>",
		"DW_OP_shra": ">>",
	}

	i = 0
	while i < len(lines):
		m = re.match(r"^\s*\d+:\s+(DW_OP_\S+)(?:\s+(.*))?$", lines[i])
		if not m:
			return None
		op = m.group(1)
		rest = (m.group(2) or "").strip()

		if op == "DW_OP_fbreg":
			off = int(rest, 0)
			if regs is not None and "fbreg" in regs:
				stack.append(regs["fbreg"] + off)
			else:
				stack.append(format_reg_offset("fbreg", off))
		elif re.match(r"^DW_OP_breg(\d+|x)$", op):
			bm = re.match(r"^(?:(\d+)\s+)?(-?\d+|0x[0-9a-fA-F]+)(?:\s+\[(\$[^\]]+)\])?$", rest)
			if not bm:
				return None
			off = int(bm.group(2), 0)
			reg = bm.group(3) or "$reg{}".format(bm.group(1) or op[10:])
			if regs is not None and reg in regs:
				stack.append(regs[reg] + off)
			else:
				stack.append(format_reg_offset(reg, off))
		elif re.match(r"^DW_OP_reg(\d+|x)$", op):
			rm = re.match(r"^(?:\d+\s+)?(?:\[(\$[^\]]+)\])?$", rest)
			reg = (rm.group(1) if rm and rm.group(1) else None) or "$reg{}".format(op[9:])
			if regs is not None and reg in regs:
				stack.append(regs[reg])
			else:
				stack.append(reg)
			is_value = True
		elif op in ("DW_OP_const1u", "DW_OP_const1s", "DW_OP_const2u", "DW_OP_const2s",
					"DW_OP_const4u", "DW_OP_const4s", "DW_OP_const8u", "DW_OP_const8s",
					"DW_OP_constu", "DW_OP_consts", "DW_OP_addr"):
			val = int(rest, 0)
			stack.append(val)
		elif op.startswith("DW_OP_lit"):
			stack.append(int(op[9:]))
		elif op == "DW_OP_plus_uconst":
			if not stack:
				return None
			off = int(rest, 0)
			top = stack.pop()
			if isinstance(top, int):
				stack.append(top + off)
			else:
				stack.append(format_reg_offset("({})".format(top) if " " in str(top) else str(top), off))
		elif op == "DW_OP_deref" or op == "DW_OP_deref_size":
			if not stack:
				return None
			size = int(rest, 0) if op == "DW_OP_deref_size" else 8
			addr = stack.pop()
			if isinstance(addr, int) and read_mem is not None:
				stack.append(read_mem(addr, size))
			else:
				ctype = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uintptr_t"}.get(size, "uint{}_t".format(size * 8))
				addr_s = "0x{:x}".format(addr) if isinstance(addr, int) else str(addr)
				stack.append("*({} *)({})".format(ctype, addr_s))
		elif op in binops:
			if len(stack) < 2:
				return None
			rhs = stack.pop()
			lhs = stack.pop()
			if isinstance(lhs, int) and isinstance(rhs, int):
				if op == "DW_OP_and": stack.append(lhs & rhs)
				elif op == "DW_OP_or": stack.append(lhs | rhs)
				elif op == "DW_OP_xor": stack.append(lhs ^ rhs)
				elif op == "DW_OP_plus": stack.append(lhs + rhs)
				elif op == "DW_OP_minus": stack.append(lhs - rhs)
				elif op == "DW_OP_mul": stack.append(lhs * rhs)
				elif op == "DW_OP_div" and rhs != 0: stack.append(lhs // rhs)
				elif op == "DW_OP_mod" and rhs != 0: stack.append(lhs % rhs)
				elif op == "DW_OP_shl": stack.append(lhs << rhs)
				elif op in ("DW_OP_shr", "DW_OP_shra"): stack.append(lhs >> rhs)
				else: return None
			else:
				lhs_s = "0x{:x}".format(lhs) if isinstance(lhs, int) else str(lhs)
				rhs_s = str(rhs)
				stack.append("({} {} {})".format(lhs_s, binops[op], rhs_s))
		elif op == "DW_OP_neg":
			if not stack:
				return None
			val = stack.pop()
			stack.append(-val if isinstance(val, int) else "-({})".format(val))
		elif op == "DW_OP_not":
			if not stack:
				return None
			val = stack.pop()
			stack.append(~val if isinstance(val, int) else "~({})".format(val))
		elif op == "DW_OP_stack_value":
			is_value = True
		elif op == "DW_OP_entry_value":
			# Consume indented sub-expression lines following DW_OP_entry_value
			sub_indent = len(lines[i]) - len(lines[i].lstrip())
			sub_lines = []
			while i + 1 < len(lines) and (len(lines[i + 1]) - len(lines[i + 1].lstrip())) > sub_indent:
				i += 1
				sub_lines.append(lines[i])
			sub_res = eval_dwarf_expr("\n".join(sub_lines))
			stack.append("entry({})".format(sub_res if sub_res else "..."))
		elif op == "DW_OP_piece":
			size = int(rest, 0)
			if stack:
				val = stack.pop()
				prefix = "val=" if is_value else "addr="
				val_s = "0x{:x}".format(val) if isinstance(val, int) else str(val)
				pieces.append("{}B@{}{}".format(size, prefix, val_s))
			else:
				pieces.append("{}B@undef".format(size))
			is_value = False
		elif op == "DW_OP_nop":
			pass
		else:
			return None
		i += 1

	if pieces:
		return "pieces: " + ", ".join(pieces)
	if not stack:
		return None
	top = stack[-1]
	if isinstance(top, int):
		return "value: {} (0x{:x})".format(top, top & 0xffffffffffffffff) if is_value else "at 0x{:016x}".format(top)
	return ("value: " if is_value else "at ") + str(top)


def decode_complex(complex_expr, regs=None, read_mem=None):
	decoded = eval_dwarf_expr(complex_expr, regs=regs, read_mem=read_mem)
	if decoded is not None:
		return decoded
	return indent_string(complex_expr)


def read_mem_int(addr, size):
	data = readmem(addr, size)
	return int.from_bytes(data, "little")


def parse_bt_frames(pid):
	frames = []
	out = exec_crash_command("bt {}".format(pid))
	for line in out.splitlines():
		fm = re.match(r"^\s*#(\d+)\s+\[([0-9a-fA-F]+)\]\s+(\S+)\s+at\s+([0-9a-fA-F]+)", line)
		if fm:
			sp = int(fm.group(2), 16)
			frames.append({
				"num": int(fm.group(1)),
				"sp": sp,
				"rsp": sp + 8 if int(fm.group(1)) > 0 else sp,
				"func": fm.group(3),
				"addr": int(fm.group(4), 16),
				"fbreg": None,
			})
	for i in range(len(frames) - 1):
		frames[i]["fbreg"] = frames[i + 1]["sp"] + 8
	return frames


def get_text_addr_vars(func, text_addr, regs=None, read_mem=None):
	indent_str = "\t"
	indent_str2 = "\t\t"
	print("")
	print("checking symbols in scope at 0x{:016x} in '{}'".format(text_addr, func))
	print("{}{}".format(indent_str, func_string(func)))
	print("")

	r = exec_crash_command("gdb info scope *0x{:016x}".format(text_addr))

	m = re.match(r"^Scope for (\*0x[0-9a-fA-F]+):$[\n\r]+(.+)$", r, flags=re.MULTILINE | re.DOTALL)
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
						d = decode_complex(range_match.group('dwarf_expr'), regs=regs, read_mem=read_mem)
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
			d = decode_complex(match.group('complex_content'), regs=regs, read_mem=read_mem)
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
def get_scope(func, addr, regs=None, read_mem=None):
#	print("func: {}".format(func))
	get_text_addr_vars(func, addr, regs=regs, read_mem=read_mem)


# -p <pid>
# -r - address(es) given is a return address...get the scope for the previous instruction
#      currently the default


if __name__ == "__main__":
	try:
#		opts_parser = argparse.ArgumentParser(version='0.01')
		opts_parser = argparse.ArgumentParser()
		opts_parser.add_argument('addrs', metavar='N', type=str, nargs='*',
			help='addresses for which to display scope')
		opts_parser.add_argument('--pid', '-p', dest='pid', type=int, default=0,
			help='resolve frame base/stack addresses using backtrace of PID')
		opts_parser.add_argument('--return', '-r', dest='return_addr', default=False, action='store_true',
			help='the address(es) is a return address, so get scope of previous instrution')

		args = opts_parser.parse_args()

		if len(args.addrs) < 1 and not args.pid:
			opts_parser.print_help()
			sys.exit(1)

		frames = parse_bt_frames(args.pid) if args.pid else []
		read_mem = read_mem_int if args.pid else None

		if args.pid and not args.addrs:
			for f in frames:
				check_addr = f["addr"] if f["num"] == 0 else previous_insn_addr(f["addr"])
				if not check_addr:
					continue
				regs = {"fbreg": f["fbreg"], "$rsp": f["rsp"]} if f["fbreg"] else None
				get_scope(f["func"], check_addr, regs=regs, read_mem=read_mem)
			sys.exit(0)

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
			regs = None
			if frames:
				for f in frames:
					if f["addr"] == req_addr or f["addr"] == check_addr or f["func"] == req_func:
						if f["fbreg"]:
							regs = {"fbreg": f["fbreg"], "$rsp": f["rsp"]}
						break
			if check_addr:
				get_scope(req_func, check_addr, regs=regs, read_mem=read_mem)

	except crash.error as e:
		print("failed: '{}'".format(sys.argv))
		print("error: {}".format(e))


#	get_scope(48600, 0xffffffff811ab29a)


# vim: sw=4 ts=4 noexpandtab
