#!/usr/bin/python
 
from pykdump.API import *

def ind(i):
	return "{spaces}".format(spaces = ' ' * 4 * i)

def enum_string(enum_name, val):
	str = "UNKNOWN"
	_enum_mapping = {}
	try:
		_S_enum_info = EnumInfo("enum " + enum_name)
		if _S_enum_info is None:
			return str
		_enum_key_list = sorted(_S_enum_info, key=lambda x: _S_enum_info[x])
		str = _enum_key_list[val]
	except Exception as ex:
		pass
	return str


def get_enum_bits_string(enum, val):
	strings = []
	for bit in range(0, 63):
		if val & (1 << bit):
			strings.append(enum_string(enum, bit))
			val = val & (~(1 << bit))
	if val:
		strings.append("0x{:x}".format(val))
	return " | ".join(strings)

__DELEG_FLAGS_ENUM_C = '''
enum deleg_flags_enum {
	NFS_DELEGATION_NEED_RECLAIM = 0,
	NFS_DELEGATION_RETURN,
	NFS_DELEGATION_RETURN_IF_CLOSED,
	NFS_DELEGATION_REFERENCED,
	NFS_DELEGATION_RETURNING,
	NFS_DELEGATION_REVOKED,
	NFS_DELEGATION_TEST_EXPIRED,
	NFS_DELEGATION_INODE_FREEING,
	NFS_DELEGATION_RETURN_DELAYED
};
'''
DELEG_FLAGS_ENUM = CEnum(__DELEG_FLAGS_ENUM_C)


def get_deleg_flags_string(flags):
	strings = []
	for n in DELEG_FLAGS_ENUM.getAllNames():
		val = DELEG_FLAGS_ENUM.getByName(n)
		if flags & (1 << val):
			strings.append(n[15:])
			flags = flags & (~(1 << val))
	if flags:
		srings.append("0x{:x}".format(flags))
	return " | ".join(strings)


def show_nfs_server(server):
	deleg_gen = server.delegation_gen
	delegs = readSUListFromHead(server.delegations, "super_list", "struct nfs_delegation", maxel=10000000)

	flag_counts = {}
	for deleg in delegs:
		flag_counts.update({deleg.flags: flag_counts.get(deleg.flags, 0) + 1})

	print("{}(struct nfs_server *)0x{:016x} delegations: {}".format(ind(1), server, len(delegs)))
	client = server.nfs_client
	state_string = get_enum_bits_string('nfs4_client_state', client.cl_state)
	print("{}(struct nfs_client *)0x{:016x} - client state: 0x{:x} - {}".format(ind(2), client, client.cl_state, state_string))

	if len(delegs):
		print("{}delegation flags:".format(ind(2)))
		for flags in flag_counts:
			print("{}{} - 0x{:x} - {}".format(ind(3), flag_counts[flags], flags, get_deleg_flags_string(flags)))


if __name__ == "__main__":
	super_blocks = readSymbol("super_blocks")
	sb_list = readSUListFromHead(super_blocks, "s_list", "struct super_block")
	nfs_sbs = []
	for sb in sb_list:
		s_type = sb.s_type.name
		if s_type == "nfs" or s_type == "nfs4":
			nfs_sbs.append(sb)

	for nfs_sb in nfs_sbs:
		print("(struct super_block *)0x{:016x}".format(nfs_sb))
		print("{}{}".format(ind(1), get_pathname(nfs_sb.s_root, 0)))
		nfs_server = readSU("struct nfs_server", nfs_sb.s_fs_info)
		show_nfs_server(nfs_server)


# vim: sw=4 ts=4 noexpandtab
