#!/usr/bin/python

import sys
import inspect
from pykdump.API import *
from crash import get_pathname
import traceback

def ind(i):
    return "{}".format(' ' * 4 * i)

def arg_value(arg):
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

def print_dentry_paths(dentry, vfsmnt=0, ilvl=0):
	vfsmnt_list = []

	print("{}(struct dentry *)0x{:016x}".format(ind(ilvl), dentry), end='')
	if vfsmnt:
		print(", (struct vfsmnt *)0x{:016x}".format(vfsmnt), end='')
		vfsmnt_list.append(readSU("struct vfsmount", vfsmnt))

	try:
		dentry = readSU("struct dentry", dentry)
	except Exception as e:
		print("exception in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
		print("\nexception in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
		traceback.print_tb(sys.exc_info()[2])
		print("")
		pass
		return

	sb = dentry.d_sb
	print(", (struct super_block *)0x{:016x}".format(sb))

	if not struct_exists("struct mount"):
#		mount = readSU("struct mount", container_of(vfsmnt, "struct mount", "mnt"))
		print(" - (struct vfsmount *)0x{:016x} - flags: 0x{:04x} - {}".format(
			vfsmnt, vfsmnt.mnt_flags, get_pathname(dentry, vfsmnt)))

		return



	try:
		if vfsmnt:
			mount = readSU("struct mount", container_of(vfsmnt, "struct mount", "mnt"))
			print(" - (struct mount *)0x{:016x} - (struct vfsmount *)0x{:016x} - flags: 0x{:04x} - {}".format(
				mount, vfsmnt, vfsmnt.mnt_flags, get_pathname(dentry, vfsmnt)))
		else:
			mount_list = []

			sb = dentry.d_sb
			l = readListByHead(sb.s_mounts)

			if len(l) > 0:
				print(" l has {} entries".format(len(l)))
				for le in l:
					mount = readSU("struct mount", container_of(le, "struct mount", "mnt_instance"))
#				mount_list.append(readSU(container_of(l, "mount", "mnt_instance"), "struct mount"))
					mount_list.append(mount)

				for mount in mount_list:

					print(" - (struct mount *)0x{:016x} - (struct vfsmount *)0x{:016x} - flags: 0x{:04x} - {}".format(
						mount, mount.mnt, mount.mnt.mnt_flags, get_pathname(dentry, mount.mnt)))
			else:
				print(" - (struct dentry *)0x{:016x} - {}".format(dentry, get_pathname(dentry, 0)))

#				vfsmnt_list.append(mount.mnt)
#			dl = readSUListFromHead(i_dentry, "d_alias", "struct dentry")

	except Exception as e:
		try:
			exc_info = sys.exc_info()
			print("exception in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
			print("")

			pass
		finally:
			traceback.print_exception(*exc_info)
			del exc_info

#	for vfsmnt in vfsmnt_list:
#		print(" - (struct vfsmnt *)0x{:016x} - flags: {:04x} - {}".format(vfsmnt, vfsmnt.mnt_flags, get_pathname(dentry, vfsmnt)))


def print_inode_paths(inode, ilvl=0):
	print("{}(struct inode *)0x{:016x}".format(ind(ilvl), inode))
	try:
		inode = readSU("struct inode", inode)
		if inode.hasField("i_dentry"):
			i_dentry = inode.i_dentry
			try:
				dl = readSUListFromHead(i_dentry, "d_alias", "struct dentry")
			except:
				dl = readSUListFromHead(i_dentry, "d_u", "struct dentry")

			num_dentries = len(dl)


			for dentry in dl:
				print_dentry_paths(dentry, ilvl=ilvl+1)
#				print("{}{}".format(ind(ilvl+1), get_pathname(dentry, 0)))

	except Exception as e:
		print("error reading inode at {}: {}".format(inode, e))
		pass

def print_path_paths(path, ilvl=0):
	print("{}(struct path *)0x{:016x}".format(ind(ilvl), path))
	try:
		path = readSU("struct path", path)
#		print("{}{}".format(ind(ilvl+1), get_pathname(path.dentry, path.mnt)))
		try:
			print_dentry_paths(path.dentry, path.mnt, ilvl=ilvl+1)
		except:
			print("bah")
	except Exception as e:
		print("exception in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
		pass

def print_file_paths(filp, ilvl=0):
	print("{}(struct file *)0x{:16x}".format(ind(ilvl), filp))
	try:
		filp = readSU("struct file", filp)
		if filp.f_path.dentry:
			print_path_paths(filp.f_path, ilvl=ilvl+1)
	except Exception as e:
		
		print("exception in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
		pass

def print_mm_paths(mm, ilvl=0):
	print("{}(struct mm_struct *)0x{:016x}".format(ind(ilvl), mm))
	try:
		mm = readSU("struct mm_struct", mm)
		if mm.exe_file:
			print_file_paths(mm.exe_file, ilvl=ilvl+1)
	except Exception as e:
		print("exception in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
		pass

def print_vma_paths(vma, ilvl=0):
	print("{}(struct vm_area_struct *)0x{:016x}".format(ind(ilvl), vma))
	try:
		vma = readSU("struct vm_area_struct", vma)
		if vma.vm_file:
			print_file_paths(vma.vm_file, ilvl=ilvl+1)
		elif vma.vm_mm:
			print_mm_paths(vma.vm_mm, ilvl=ilvl+1)
	except Exception as e:
		print("exception in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
		pass
#[308] vm | grep '/u01/app/informatica/product/10.4/java/bin/java'
#[309] vm_area_struct.vm_mm ffff88081bbee530
#[310] vm_area_struct.vm_mm ffff88081bbee468
#[311] kmem -s ffff88081bbee468

def print_aspace_paths(aspace, ilvl=0):
	print("{}(struct address_space *)0x{:016x}".format(ind(ilvl), aspace))
	try:
		aspace = readSU("struct address_space", aspace)
		print_inode_paths(aspace.host, ilvl=ilvl+1)
	except Exception as e:
		print("exception in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
		pass

def print_page_paths(page, ilvl=0):
	print("{}(struct page *)0x{:016x}".format(ind(ilvl), page))
	try:
		page = readSU("struct page", page)
		print_aspace_paths(page.mapping, ilvl=ilvl+1)
	except Exception as e:
		print("exception in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
		pass

def print_kernfs_node_paths(kn, ilvl=0):
	try:
		p = ""
		while kn:
			kn = readSU("struct kernfs_node", kn)
			if kn.name and p == "":
				p = kn.name
			elif kn.name:
				p = "{}/{}".format(kn.name, p)
			if kn == kn.parent:
				break
			kn = kn.parent
		print("{}(struct kernfs_node *)0x{:016x} = '{}'".format(ind(ilvl), kn, p))
	except Exception as e:
		print("{}(struct kernfs_node *)0x{:016x}".format(ind(ilvl), kn))
		print("exception in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
		pass
def print_kobject_paths(kobj, ilvl=0):
	try:
		p = ""
		while kobj:
			kobj = readSU("struct kobject", kobj)
			if kobj.name and p == "":
				p = kobj.name
			elif kobj.name:
				p = "{}/{}".format(kobj.name, p)
			if kobj == kobj.parent:
				break
			kobj = kobj.parent
		print("{}(struct kobject *)0x{:016x} = '{}'".format(ind(ilvl), kobj, p))
	except Exception as e:
		print("{}(struct kobject *)0x{:016x}".format(ind(ilvl), kobj))
		print("exception in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
		pass
def print_device_paths(dev, ilvl=0):
	try:
		p = ""
		while dev:
			dev = readSU("struct device", dev)
			if dev.init_name and p == "":
				p = dev.init_name
			elif dev.init_name:
				p = "{}/{}".format(dev.init_name, p)
			if dev == dev.parent:
				break
			dev = dev.parent
		print("{}(struct device *)0x{:016x} = '{}'".format(ind(ilvl), dev, p))
	except Exception as e:
		print("{}(struct device *)0x{:016x}".format(ind(ilvl), dev))
		print("exception in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
		pass


def print_unknown_paths(addr, ilvl=0):
	print("{}unable to determine type to print for address 0x{:016x}".format(ind(ilvl), addr))

def get_print_func_by_type(type_str):
	if type_str == "inode":
		print_func = print_inode_paths
	elif type_str == "vma" or type_str == "vm_area_struct":
		print_func = print_vma_paths
	elif type_str == "mm_struct" or type_str == "mm":
		print_func = print_mm_paths
	elif type_str == "file" or type_str == "filp":
		print_func = print_file_paths
	elif type_str == "dentry":
		print_func = print_dentry_paths
	elif type_str == "page":
		print_func = print_page_paths
	elif type_str == "address_space" or type_str == "aspace" or type_str == "mapping":
		print_func = print_aspace_paths
	elif type_str == "path":
		print_func = print_path_paths
	elif type_str == "kernfs_node":
		print_func = print_kernfs_node_paths
	elif type_str == "kobject":
		print_func = print_kobject_paths
	elif type_str == "device":
		print_func = print_device_paths
	else:
		print_func = print_unknown_paths
#	print("print_func: {}".format(print_func))
	return print_func

def call_print_func(print_func, addr, ilvl=0):
	print_func(addr, ilvl=ilvl)

if __name__ == "__main__":
	print_func = None
	type_str = sys.argv[1]

#	print("trying to get print function for type {}".format(type_str))
	print_func = get_print_func_by_type(type_str)

	if print_func is None or print_func is print_unknown_paths:
		print_func = print_unknown_paths
		args = sys.argv[1:]
	else:
		args = sys.argv[2:]

	for addr in args:
		try:
#			print("printing arg '{} as {}".format(addr, type_str))
			addr = arg_value(addr)
			call_print_func(print_func, addr)
		except Exception as e:
			print("exception in {}: {}\n{}".format(inspect.currentframe().f_code.co_name, e, sys.exc_info()[2]))
			pass

# vim: sw=4 ts=4 noexpandtab
