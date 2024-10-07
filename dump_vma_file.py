#!/usr/bin/python

from __future__ import print_function

from pykdump.API import *
import sys

PAGE_SIZE = crash.PAGESIZE

DEBUG = 0

null_page = "\0"*PAGE_SIZE

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

def usage():
	print("usage: dump_inode_pages <address of inode>")


def struct__has_member(str, mbr):
	return (member_size("struct " + str, mbr) != -1)

if struct__has_member("file", "f_path"):
	def file_get_dentry(filp):
		try:
			return Deref(filp.f_path.dentry)
		except:
			return 0
	def file_get_vfsmnt(filp):
		try:
			return Deref(filp.f_path.mnt)
		except:
			return 0
else:
	def file_get_dentry(filp):
		try:
			return Deref(filp.f_dentry)
		except:
			return 0
	def file_get_vfsmnt(filp):
		try:
			return Deref(filp.f_vfsmnt)
		except:
			return 0

def inode_paths(inode):
	ret = []
	try:
		inode = readSU("struct inode", inode)
		if inode.hasField("i_dentry"):
			i_dentry = inode.i_dentry
			dl = readSUListFromHead(i_dentry, "d_alias", "struct dentry")
			num_dentries = len(dl)

			for dentry in dl:
				p = get_pathname(dentry, 0)
				ret.append(p)
	except Exception as ex:
		print("error reading inode at {}: {}".format(inode, ex))
		pass
	return ret


vmemmap_vaddr = 0
vmemmap_end = 0
kvbase = 0
page_struct_size = 0
def page_address(page_addr):
	global vmemmap_vaddr
	global vmemmap_end
	global kvbase
	global page_struct_size

	# just in case we somehow get here without this value
	if vmemmap_vaddr == 0:
		return 0

	# get start of the page structs
	# help -m | grep vmemmap_vaddr

	# get page struct offset
	# *page - vmemmap_vaddr

	# phys page number is page struct offset divided by 4
	# multiply by 0x1000 to get the physical address

	page_struct_offset = page_addr - vmemmap_vaddr
	phys_page_num = long(page_struct_offset / page_struct_size)
	phys_address = phys_page_num * 0x1000
	virt_address = phys_address + kvbase

	if DEBUG:
		print("page_addr = 0x{:016x}".format(page_addr))
		print("vmemmap_vaddr = 0x{:016x}".format(vmemmap_vaddr))
		print("page_struct_offset = 0x{:016x}".format(page_struct_offset))
		print("phys_page_num = 0x{:016x}".format(phys_page_num))
		print("phys_address = 0x{:016x}".format(phys_address))
		print("virt_address = 0x{:016x}".format(virt_address))
	return virt_address

def page_address_slow(page_addr):
	ret = exec_crash_command("kmem 0x%016x" % page_addr)
	ret2 = ()
	for l in ret.split("\n"):
		if "ffff" in l or 'c000' in l:
			phys = l.split()[1]
			ret2 = exec_crash_command("ptov 0x%s" % phys)
			break
	for l in ret2.split("\n"):
		if "ffff" in l or 'c000' in l:
			return int(l.split()[0], 16)
	return 0

def aspace_pages_list(aspace):
	aspace = readSU("struct address_space", aspace)
	pages = []

	nrpages = aspace.nrpages
	if nrpages == 0:
		return pages
	if nrpages == 1:
		# if there's just one page, it's a direct pointer to the page, rather than a tree
		if DEBUG:
			print("one page...  appending 0x{:016x}".format(aspace.page_tree.rnode))
		pages.append(aspace.page_tree.rnode)
		return pages
	for l in exec_crash_command("tree -t ra 0x{:016x}".format(aspace.page_tree)).split("\n"):
		if l != '':
			addr = get_arg_value(l)
			if DEBUG:
				print("page: '{}' => 0x{:016x}".format(l, addr))
			pages.append(addr)
	return pages

def dump_inode_pages_nullfill(inode):
	inode = readSU("struct inode", inode)
	aspace = inode.i_mapping
	page_tree = aspace.page_tree
	pages_required = int((inode.i_size + PAGE_SIZE - 1) / PAGE_SIZE)

	if DEBUG:
		print("inode is 0x{:016x}".format(inode))
		print("inode size is {}".format(inode.i_size))
		print("address_space is at 0x{:016x}".format(aspace))
		print("page_tree is at 0x{:016x}".format(page_tree))
		print("address_space has {} pages".format(aspace.nrpages))
		print("a full page tree would contain {} pages".format(pages_required))

	if aspace.nrpages != pages_required:
		print("WARNING: the number of pages in the address_space ({}) does not match the number of pages required ({}) to accommodate the size of the inode ({} bytes)".format(
			aspace.nrpages, pages_required, inode.i_size))

	pages = aspace_pages_list(aspace)
	if DEBUG > 1:
		print("pages: {}".format(pages))

	if (pages_required != len(pages)):
		print("WARNING: the number of pages present in the address_space ({}) does not match the number of pages required ({}) to accommodate the size of the inode ({} bytes)".format(
			len(pages), pages_required, inode.i_size))
		print("Attempting to continue with pages of zero")
		# we'll have to fill missing pages with '\0'

	out = open("inode-0x{:016x}.bin".format(inode), "wb")

	remain = inode.i_size
	cur_idx = 0
	for p in pages:
		try:
			page = readSU("struct page", p)
			pg_idx = page.index
		except:
			page = 0
			pg_idx = cur_idx

		while cur_idx < pg_idx:
			out.write(null_page)
			cur_idx += 1

		if p != 0:
			addr = page_address(p)
		else:
			addr = 0

		if DEBUG:
			print("page 0x{:016x} => address 0x{:016x}".format(p, addr))
			print


		if addr != 0:
			s = min(PAGE_SIZE, remain)
			try:
				mem = readmem(addr, s);

#				mem = bytearray(readmem(addr, s), encoding='ascii')
			except Exception as e:
				print("error trying to readmem({:016x}, {}): {}".format(addr, s, e))
				mem = bytearray("\0"*s, encoding='ascii')
				pass
			remain -= s
			out.write(mem)
		cur_idx += 1
	out.close()

def get_vmemmap_addrs():
	global vmemmap_vaddr
	global vmemmap_end
	global kvbase
	global page_struct_size

	for l in exec_crash_command("help -m").split("\n"):
		if l != '':
			tmp = l.split(": ")
			if len(tmp) == 2:
				key = tmp[0].strip()

				match = re.search('^([0-9a-fA-F]+)', tmp[1].strip())
				if match:
					val = get_arg_value(match.group(1))

					if DEBUG:
						print("*{}* => *{}*".format(key, val))

					if key == 'vmemmap_vaddr':
						vmemmap_vaddr = val
						if DEBUG:
							print("got vmemmap_vaddr: 0x{:016x}".format(vmemmap_vaddr))
					elif key == 'vmemmap_end':
						vmemmap_end = val
						if DEBUG:
							print("got vmemmap_end: 0x{:016x}".format(vmemmap_end))
					elif key == 'kvbase':
						kvbase = val
						if DEBUG:
							print("got kvbase: 0x{:016x}".format(kvbase))

			page_struct_size = struct_size("struct page")
	if vmemmap_vaddr == 0 or vmemmap_end == 0:
		print("Error attempting to get vmemmap start and endpoints")



def dump_vma_file(addr):
	vma = readSU("struct vm_area_struct", addr)
	f = vma.vm_file
	inode = f.f_inode
	inode_file = "inode-0x{:016x}.bin".format(inode)

#	print("paths:")
#	paths = inode_paths(inode)
#	for p in paths:
#		print("  {}".format(p))
#	path0 = paths[0]
#	print("{} - {}".format(path0, path0.split("/")[-1]))

	dentry = file_get_dentry(f)
	vfsmnt = file_get_vfsmnt(f)

	if dentry:
		pathname = get_pathname(dentry, vfsmnt)

	else:
		pathname = inode_file

#	exe_file =
#	inode_paths

	dump_inode_pages_nullfill(inode)

	print("actual path: {}".format(pathname))
	print("actual path dirname: {}".format(os.path.dirname(pathname)))
	print("actual path basename: {}".format(os.path.basename(pathname)))

	re_name = "libs/{}".format(os.path.basename(pathname))

#	subdir = 
	try:
		os.mkdir("libs")
	except: # it probably already exists
		pass
#	os.rename(pathname, "libs/{}".format
	os.rename(inode_file, re_name)
	print("output to {}".format(re_name))



if __name__ == "__main__":
	argc = len(sys.argv)

	if vmemmap_vaddr == 0:
		get_vmemmap_addrs()

#	print("page size: {}".format(crash.PAGESIZE))
#	print("sys_info: {}".format(sys_info))

	if vmemmap_vaddr == 0:
		print("Unable to determine starting address for virtual memory")
		print("only dumping available information about page tree")

		print("falling back to slow method of determining page addresses")
		page_address = page_address_slow

#		sys.exit()

	if argc < 2:
		usage()
	else:
		try:
			for vma_str in sys.argv[1:]:
				vma_addr = get_arg_value(vma_str)
				dump_vma_file(vma_addr)

#			for inode_str in sys.argv[1:]:
#				inode_addr = get_arg_value(inode_str)
#				dump_inode_pages_nullfill(inode_addr)

		except Exception as err:
			print("Error occurrred: {}".format(str(err)))
			usage()
			raise

# vim: sw=4 ts=4 noexpandtab
