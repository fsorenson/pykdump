
from pykdump.API import *
try:
	from pykdump.Generic import SUInfo
except:
	from pykdump.datatypes import SUInfo
from LinuxDump.Tasks import TaskTable
from LinuxDump.inet.proto import *
from libs.sorenson import *

verbose = 0


def list_sb_mountpoints(sb):
	paths = []

	s_mounts = readSUListFromHead(sb.s_mounts, "mnt_instance", "struct mount")
	for mount in s_mounts:
		path = get_pathname(mount.mnt_mountpoint, mount.mnt)
		print("    (struct mount *)0x{:016x} - {}  {}".format(mount, mount.mnt_devname, path))

def do_one_sb(sb):
	print("0x{:016x} - {} filesystem - {}".format(sb, sb.s_type.name, sb.s_id))
	if verbose:
		list_sb_mountpoints(sb)

	s_dentry_lru = sb.s_dentry_lru
	node = s_dentry_lru.node

	global_nr_items = node.lru.nr_items
	cgroup_nr_items = node.nr_items

	print("  (struct list_lru_node *)0x{:016x} - list entries - global node LRU: {}, cgroup LRU: {}".format(node, global_nr_items, cgroup_nr_items))


#	crash> list_lru.node ffff9f978b8684c0
#  node = 0xffff9f9789938cc0,

#crash> list_lru_node.lru,memcg_lrus,nr_items 0xffff9f9789938cc0 -d
#  lru = {
#    list = {
#      next = 0xffff9f9789938cc8,
#      prev = 0xffff9f9789938cc8
#    },
#    nr_items = 0      # global node LRU list is empty
#  },
#  memcg_lrus = 0xffff9f9f1738e000,
#  nr_items = 24876    # but there are some cgroup LRU lists

#crash> list_lru_memcg.lru 0xffff9f9f1738e000
#  lru = 0xffff9f9f1738e010



if __name__ == "__main__":
	import argparse
	opts_parser = argparse.ArgumentParser()

	opts_parser.add_argument('--verbose', '-v', dest='verbose', default=0, action = 'count', help = "increase verbosity")
	opts, args = opts_parser.parse_known_args(sys.argv[1:])

	verbose = opts.verbose

#	print("type: {}".format(cmd_opts.struct_type))
#	print("remaining args: {}".format(*args))


#       if len(sys.argv) > 1:
	super_blocks = readSymbol("super_blocks")
	sb_list = readSUListFromHead(super_blocks, "s_list", "struct super_block")
	for sb in sb_list:
		do_one_sb(sb)


# vim: sw=4 ts=4 noexpandtab
