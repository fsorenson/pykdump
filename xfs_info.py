#!/usr/bin/python

from __future__ import print_function

#from fs_lib import *
#from misc.percpu import get_per_cpu
from pykdump.API import *
try:
	from pykdump.Generic import SUInfo
except:
	from pykdump.datatypes import SUInfo
from LinuxDump.Tasks import TaskTable
from LinuxDump.inet.proto import *
from libs.sorenson import *


from fs_lib import *
#import ppstruct_vars

def ntohll(x):
	if sys.byteorder == 'little':
		return (
			((x << 56) & 0xff00000000000000) |
			((x << 40) & 0x00ff000000000000) |
			((x << 24) & 0x0000ff0000000000) |
			((x << 8) & 0x000000ff00000000) |
			((x >> 8) & 0x00000000ff000000) |
			((x >> 24) & 0x0000000000ff0000) |
			((x >> 40) & 0x000000000000ff00) |
			(x >> 56) & 0x000000000000000ff)
	else:
		return x
def htonll(x):
	return ntohll(x)


BBSHIFT = 9
BBSIZE = (1 << BBSHIFT)
BBMASK = (BBSIZE - 1)
XFS_SB_MAGIC =			0x58465342     # /* 'XFSB' */
XFS_SB_VERSION_1 =		1              # /* 5.3, 6.0.1, 6.1 */
XFS_SB_VERSION_2 =		2              # /* 6.2 - attributes */
XFS_SB_VERSION_3 =		3              # /* 6.2 - new inode version */
XFS_SB_VERSION_4 =		4              # /* 6.2+ - bitmask version */
XFS_SB_VERSION_5 =		5			# /* CRC enabled filesystem */

__XFS_SB_VERSION_FLAGS = '''
#define XFS_SB_VERSION_NUMBITS         0x000f
#define XFS_SB_VERSION_ALLFBITS        0xfff0
#define XFS_SB_VERSION_ATTRBIT         0x0010
#define XFS_SB_VERSION_NLINKBIT        0x0020
#define XFS_SB_VERSION_QUOTABIT        0x0040
#define XFS_SB_VERSION_ALIGNBIT        0x0080
#define XFS_SB_VERSION_DALIGNBIT       0x0100
#define XFS_SB_VERSION_SHAREDBIT       0x0200
#define XFS_SB_VERSION_LOGV2BIT        0x0400
#define XFS_SB_VERSION_SECTORBIT       0x0800
#define XFS_SB_VERSION_EXTFLGBIT       0x1000
#define XFS_SB_VERSION_DIRV2BIT        0x2000
#define XFS_SB_VERSION_BORGBIT         0x4000  /* ASCII only case-insens. */
#define XFS_SB_VERSION_MOREBITSBIT     0x8000
'''
XFS_SB_VERSION_FLAGS = CDefine(__XFS_SB_VERSION_FLAGS)

XFS_TRANS_HEADER_MAGIC	= 0x5452414e	# /* TRAN */
XFS_BMAP_MAGIC			= 0x424d4150	# /* 'BMAP' */
XFS_BMAP_CRC_MAGIC		= 0x424d4133	# /* 'BMA3' */
XFS_AGF_MAGIC			= 0x58414746	# /* 'XAGF' */
XFS_AGI_MAGIC			= 0x58414749	# /* 'XAGI' */
XFS_AGFL_MAGIC			= 0x5841464c	# /* 'XAFL' */
XFS_DINODE_MAGIC		= 0x494e		# /* 'IN' */
XFS_DQUOT_MAGIC			= 0x4451		# /* 'DQ' */
XFS_SYMLINK_MAGIC		= 0x58534c4d	# /* XSLM */

XFS_ABTB_MAGIC			= 0x41425442	# /* 'ABTB' for bno tree */
XFS_ABTB_CRC_MAGIC		= 423342		# /* 'AB3B' */
XFS_ABTC_MAGIC			= 0x41425443	# /* 'ABTC' for cnt tree */
XFS_ABTC_CRC_MAGIC		= 423343		# /* 'AB3C' */
XFS_IBT_MAGIC			= 0x49414254	# /* 'IABT' */
XFS_IBT_CRC_MAGIC		= 9414233		# /* 'IAB3' */
XFS_FIBT_MAGIC			= 0x46494254	# /* 'FIBT' */
XFS_FIBT_CRC_MAGIC		= 494233		# /* 'FIB3' */



def indent_str(lvl):
	return "{spaces}".format(spaces = ' ' * 4 * lvl)

def indent(lvl):
	print(indent_str(lvl), end="")



#define XFS_SB_VERSION_NUM(sbp) ((sbp)->sb_versionnum & XFS_SB_VERSION_NUMBITS)
def XFS_SB_VERSION_NUM(sbp):
	return sbp.sb_versionnum & XFS_SB_VERSION_FLAGS['XFS_SB_VERSION_NUMBITS']
#	return sbp.sb_versionnum & XFS_SB_VERSION_NUMBITS


def xfs_sb_version(sbp, flagname):
	flagname = "XFS_SB_VERSION_" + flagname
	return sbp.sb_versionnum & XFS_SB_VERSION_FLAGS[flagname]


__XFS_SB_VERSION2_FLAGS = '''
#define XFS_SB_VERSION2_RESERVED1BIT    0x00000001
#define XFS_SB_VERSION2_LAZYSBCOUNTBIT  0x00000002      /* Superblk counters */
#define XFS_SB_VERSION2_RESERVED4BIT    0x00000004
#define XFS_SB_VERSION2_ATTR2BIT        0x00000008      /* Inline attr rework */
#define XFS_SB_VERSION2_PARENTBIT       0x00000010      /* parent pointers */
#define XFS_SB_VERSION2_PROJID32BIT     0x00000080      /* 32 bit project id */
#define XFS_SB_VERSION2_CRCBIT          0x00000100      /* metadata CRCs */
#define XFS_SB_VERSION2_FTYPE           0x00000200      /* inode type in dir */

#define XFS_SB_VERSION2_OKBITS          \
		(XFS_SB_VERSION2_LAZYSBCOUNTBIT | \
		XFS_SB_VERSION2_ATTR2BIT       | \
		XFS_SB_VERSION2_PROJID32BIT    | \
		XFS_SB_VERSION2_FTYPE)
'''
XFS_SB_VERSION2_FLAGS = CDefine(__XFS_SB_VERSION2_FLAGS)

def xfs_sb_version2(sbp, flagname):
	flagname = "XFS_SB_VERSION2_" + flagname
	return sbp.sb_features2 & XFS_SB_VERSION2_FLAGS[flagname]


__XFS_SB_FEAT_FLAGS_orig = '''
#define XFS_SB_FEAT_COMPAT_ALL 0
#define XFS_SB_FEAT_COMPAT_UNKNOWN      ~XFS_SB_FEAT_COMPAT_ALL

#define XFS_SB_FEAT_RO_COMPAT_FINOBT   (1 << 0)         /* free inode btree */
#define XFS_SB_FEAT_RO_COMPAT_RMAPBT   (1 << 1)         /* reverse map btree */
#define XFS_SB_FEAT_RO_COMPAT_REFLINK  (1 << 2)         /* reflinked files */
#define XFS_SB_FEAT_RO_COMPAT_ALL \
                (XFS_SB_FEAT_RO_COMPAT_FINOBT | \
                 XFS_SB_FEAT_RO_COMPAT_RMAPBT | \
                 XFS_SB_FEAT_RO_COMPAT_REFLINK)
#define XFS_SB_FEAT_RO_COMPAT_UNKNOWN   ~XFS_SB_FEAT_RO_COMPAT_ALL

#define XFS_SB_FEAT_INCOMPAT_FTYPE      (1 << 0)        /* filetype in dirent */
#define XFS_SB_FEAT_INCOMPAT_SPINODES   (1 << 1)        /* sparse inode chunks */
#define XFS_SB_FEAT_INCOMPAT_META_UUID  (1 << 2)        /* metadata UUID */
#define XFS_SB_FEAT_INCOMPAT_ALL \
                (XFS_SB_FEAT_INCOMPAT_FTYPE|    \
                 XFS_SB_FEAT_INCOMPAT_SPINODES| \
                 XFS_SB_FEAT_INCOMPAT_META_UUID)

#define XFS_SB_FEAT_INCOMPAT_UNKNOWN    ~XFS_SB_FEAT_INCOMPAT_ALL

#define XFS_SB_FEAT_INCOMPAT_LOG_ALL 0
#define XFS_SB_FEAT_INCOMPAT_LOG_UNKNOWN        ~XFS_SB_FEAT_INCOMPAT_LOG_ALL
'''
__XFS_SB_FEAT_FLAGS = '''
#define XFS_SB_FEAT_COMPAT_ALL 0
#define XFS_SB_FEAT_COMPAT_UNKNOWN      0xffffffffffffffff

#define XFS_SB_FEAT_RO_COMPAT_FINOBT   0x1
#define XFS_SB_FEAT_RO_COMPAT_RMAPBT   0x2
#define XFS_SB_FEAT_RO_COMPAT_REFLINK  0x4
#define XFS_SB_FEAT_RO_COMPAT_ALL      0x7
#define XFS_SB_FEAT_RO_COMPAT_UNKNOWN  0xfffffffffffffff8

#define XFS_SB_FEAT_INCOMPAT_FTYPE      0x1
#define XFS_SB_FEAT_INCOMPAT_SPINODES   0x2
#define XFS_SB_FEAT_INCOMPAT_META_UUID  0x4
#define XFS_SB_FEAT_INCOMPAT_ALL        0x7

#define XFS_SB_FEAT_INCOMPAT_UNKNOWN    0xfffffffffffffff8

#define XFS_SB_FEAT_INCOMPAT_LOG_ALL 0
#define XFS_SB_FEAT_INCOMPAT_LOG_UNKNOWN        0xffffffffffffffff
'''
XFS_SB_FEAT_FLAGS = CDefine(__XFS_SB_FEAT_FLAGS)
def xfs_sb_hasfeat(sbp, flagname):
	flagname = "XFS_SB_FEAT_" + flagname
	return "?"
def xfs_sb_has_compat_feat(sbp, flagname):
	flagname = "XFS_SB_FEAT_COMPAT_" .flagname
	if sbp.sb_features_compat & XFS_SB_FEAT_FLAGS[flagname]: return 1
	return 0
def xfs_sb_has_ro_compat_feat(sbp, flagname):
	flagname = "XFS_SB_FEAT_RO_COMPAT_" + flagname
	if sbp.sb_features_ro_compat & XFS_SB_FEAT_FLAGS[flagname]: return 1
	return 0
def xfs_sb_has_incompat_feat(sbp, flagname):
	try:
		flagname = "XFS_SB_FEAT_INCOMPAT_" + flagname
#	print("XFS_SB_FEAT_FLAGS = {}".format(XFS_SB_FEAT_FLAGS))
		if sbp.sb_features_incompat & XFS_SB_FEAT_FLAGS[flagname]: return 1
	except:
		pass
	return 0
def xfs_sb_has_incompat_log_feat(sbp, flagname):
	flagname = "XFS_SB_FEAT_INCOMPAT_LOG_" + flagname
	if sbp.sb_features_log_incompat & XFS_SB_FEAT_INCOMPAT_LOG_FLAGS[flagname]: return 1
	return 0
def xfs_sb_version_hasreflink(sbp):
	if XFS_SB_VERSION_NUM(sbp) == XFS_SB_VERSION_5 and xfs_sb_has_ro_compat_feat(sbp, "REFLINK"): return 1
	return 0


#from libxfs/xfs_fs.h in xfsprogs
__XFS_FSOP_GEOM_FLAGS = '''
#define XFS_FSOP_GEOM_VERSION   0

#define XFS_FSOP_GEOM_FLAGS_ATTR        0x0001  /* attributes in use    */
#define XFS_FSOP_GEOM_FLAGS_NLINK       0x0002  /* 32-bit nlink values  */
#define XFS_FSOP_GEOM_FLAGS_QUOTA       0x0004  /* quotas enabled       */
#define XFS_FSOP_GEOM_FLAGS_IALIGN      0x0008  /* inode alignment      */
#define XFS_FSOP_GEOM_FLAGS_DALIGN      0x0010  /* large data alignment */
#define XFS_FSOP_GEOM_FLAGS_SHARED      0x0020  /* read-only shared     */
#define XFS_FSOP_GEOM_FLAGS_EXTFLG      0x0040  /* special extent flag  */
#define XFS_FSOP_GEOM_FLAGS_DIRV2       0x0080  /* directory version 2  */
#define XFS_FSOP_GEOM_FLAGS_LOGV2       0x0100  /* log format version 2 */
#define XFS_FSOP_GEOM_FLAGS_SECTOR      0x0200  /* sector sizes >1BB    */
#define XFS_FSOP_GEOM_FLAGS_ATTR2       0x0400  /* inline attributes rework */
#define XFS_FSOP_GEOM_FLAGS_PROJID32    0x0800  /* 32-bit project IDs   */
#define XFS_FSOP_GEOM_FLAGS_DIRV2CI     0x1000  /* ASCII only CI names  */
#define XFS_FSOP_GEOM_FLAGS_LAZYSB      0x4000  /* lazy superblock counters */
#define XFS_FSOP_GEOM_FLAGS_V5SB        0x8000  /* version 5 superblock */
#define XFS_FSOP_GEOM_FLAGS_FTYPE       0x10000 /* inode directory types */
#define XFS_FSOP_GEOM_FLAGS_FINOBT      0x20000 /* free inode btree */
#define XFS_FSOP_GEOM_FLAGS_SPINODES    0x40000 /* sparse inode chunks  */
#define XFS_FSOP_GEOM_FLAGS_RMAPBT      0x80000 /* reverse mapping btree */
#define XFS_FSOP_GEOM_FLAGS_REFLINK     0x100000 /* files can share blocks */
'''
XFS_FSOP_GEOM_FLAGS = CDefine(__XFS_FSOP_GEOM_FLAGS)


def xfs_sb_version_hasmorebits(sbp):
	if XFS_SB_VERSION_NUM(sbp) == XFS_SB_VERSION_5:
		return 1
	elif sbp.sb_versionnum & XFS_SB_VERSION_FLAGS['XFS_SB_VERSION_MOREBITSBIT']:
		return 1
	return 0
def xfs_sb_version_hascrc(sbp):
	if XFS_SB_VERSION_NUM(sbp) == XFS_SB_VERSION_5:
		return 1
	return 0
def xfs_sb_version_hasfinobt(sbp):
	if XFS_SB_VERSION_NUM(sbp) == XFS_SB_VERSION_5 and xfs_sb_has_ro_compat_feat(sbp, 'FINOBT'):
		return 1
	return 0

def xfs_sb_version_hasprojid32bit(sbp):
	sbp = readSU("struct xfs_sb", sbp)
	if XFS_SB_VERSION_NUM(sbp) == XFS_SB_VERSION_5:
		return 1
	if xfs_sb_version_hasmorebits(sbp) and xfs_sb_version2(sbp, 'PROJID32BIT'):
		return 1
	return 0
def xfs_sb_version_hasftype(sbp):
	if XFS_SB_VERSION_NUM(sbp) == XFS_SB_VERSION_5 and xfs_sb_has_incompat_feat(sbp, "FTYPE"):
		return 1
	if xfs_sb_version(sbp, "MOREBITSBIT") and xfs_sb_version2(sbp, "FTYPE"):
		return 1
	return 0
def xfs_version_haslogv2(sbp):
	if XFS_SB_VERSION_NUM(sbp) == XFS_SB_VERSION_5:
		return 1
	if xfs_sb_version(sbp, "LOGV2BIT"):
		return 1
	return 0


def super_block_devname(sb):
	sb = readSU("struct super_block", sb)
	try:
		first_mount = readSU("struct mount", container_of(sb.s_mounts.next, "struct mount", "mnt_instance"))
		return first_mount.mnt_devname
	except:
		return "UNKNOWN"
		pass


#static inline uint64_t xfs_mask64hi(int n) { return (uint64_t)-1 << (64 - (n)); }
#static inline uint32_t xfs_mask32lo(int n) { return ((uint32_t)1 << (n)) - 1; }
#static inline uint64_t xfs_mask64lo(int n) { return ((uint64_t)1 << (n)) - 1;}
def xfs_mask64hi(n):
	return (0xffffffffffffffff << (64 - n))
def xfs_mask32lo(n):
	return (0xffffffff & ((1 << n) - 1))
def xfs_mask64lo(n):
	return (0xffffffffffffffff & ((1 << n) - 1))

########################## xfs conversions ##########################
# 1037 /*
# 1038  * Inode number format:
# 1039  * low inopblog bits - offset in block
# 1040  * next agblklog bits - block number in ag
# 1041  * next agno_log bits - ag number
# 1042  * high agno_log-agblklog-inopblog bits - 0
# 1043  */
def cast__xfs_daddr_t(i):
	return (i & 0xffffffffffffffff)
def cast__xfs_agblock_t(i):
	return (i & 0xffffffff)
def cast__xfs_ino_t(i):
	return i & 0xffffffffffffffff
def cast__xfs_agnumber_t(i):
	return i & 0xffffffff
def cast__xfs_agino_t(i):
	return (int)(i & 0xffffffff)

#/*
# * File system block to basic block conversions.
# */
##define XFS_FSB_TO_BB(mp,fsbno) ((fsbno) << (mp)->m_blkbb_log)
def XFS_FSB_TO_BB(mp, fsbno):
	return (fsbno << (readSU("struct xfs_mount", mp).m_blkbb_log))

##define XFS_BB_TO_FSB(mp,bb)    \
#		        (((bb) + (XFS_FSB_TO_BB(mp,1) - 1)) >> (mp)->m_blkbb_log)
def XFS_BB_TO_FSB(mp, bb):
	mp = readSU("struct xfs_mount", mp)
	return ((bb + (XFS_FSB_TO_BB(mp, 1) - 1)) >> mp.m_blkbb_log)

##define XFS_BB_TO_FSBT(mp,bb)   ((bb) >> (mp)->m_blkbb_log)
def XFS_BB_TO_FSBT(mp, bb):
	return (bb >> readSU("struct xfs_mount", mp).m_blkbb_log)

#define XFS_SB_DADDR            ((xfs_daddr_t)0) /* daddr in filesystem/ag */
def XFS_SB_DADDR():
	return cast__xfs_daddr_t(0)

##define XFS_SB_BLOCK(mp)        XFS_HDR_BLOCK(mp, XFS_SB_DADDR)
def XFS_SB_BLOCK(mp):
	return XFS_HDR_BLOCK(mp, XFS_SB_DADDR)

##define XFS_BUF_TO_SBP(bp)      ((xfs_dsb_t *)((bp)->b_addr))
def XFS_BUF_TO_SBP(bp):
	return readSU("struct xfs_dsb_t", readSU("struct xfs_buf", bp).b_addr)

##define XFS_HDR_BLOCK(mp,d)     ((xfs_agblock_t)XFS_BB_TO_FSBT(mp,d))
def XFS_HDR_BLOCK(mp, d):
	return (cast__xfs_agblock_t(XFS_BB_TO_FSBT(mp, d)))


#define xfs_daddr_to_agno(mp,d) \
#	((xfs_agnumber_t)(XFS_BB_TO_FSBT(mp, d) / (mp)->m_sb.sb_agblocks))
def xfs_daddr_to_agno(mp, d):
#	return cast__xfs_agnumber_t(XFS_BB_TO_FSBT(mp, d) / mp.m_sb.sb_agblocks)
	return cast__xfs_agnumber_t(int(XFS_BB_TO_FSBT(mp, d) / mp.m_sb.sb_agblocks))
#define xfs_daddr_to_agbno(mp,d) \
#	((xfs_agblock_t)(XFS_BB_TO_FSBT(mp, d) % (mp)->m_sb.sb_agblocks))
def xfs_daddr_to_agbno(mp, d):
	return cast__xfs_agblock_t(XFS_BB_TO_FSBT(mp, d) % mp.m_sb.sb_agblocks)

##define XFS_DADDR_TO_FSB(mp,d)  XFS_AGB_TO_FSB(mp, \
#	xfs_daddr_to_agno(mp,d), xfs_daddr_to_agbno(mp,d))
def XFS_DADDR_TO_FSB(mp, d):
	return XFS_AGB_TO_FSB(mp, xfs_daddr_to_agno(mp, d),
			xfs_daddr_to_agbno(mp, d))

##define XFS_FSB_TO_DADDR(mp,fsbno)      XFS_AGB_TO_DADDR(mp, \
#	XFS_FSB_TO_AGNO(mp,fsbno), XFS_FSB_TO_AGBNO(mp,fsbno))
def XFS_FSB_TO_DADDR(mp, fsbno):
	return XFS_AGB_TO_DADDR(mp, XFS_FSB_TO_AGNO(mp,fsbno),
			XFS_FSB_TO_AGBNO(mp,fsbno))

# #define XFS_INO_MASK(k)         (__uint32_t)((1ULL << (k)) - 1)
def XFS_INO_MASK(k):
	return ((1 << k) - 1) & 0xffffffff

#1045 #define XFS_INO_OFFSET_BITS(mp)     (mp)->m_sb.sb_inopblog
def XFS_INO_OFFSET_BITS(mp):
	return readSU("struct xfs_mount", mp).m_sb.sb_inopblog

#1046 #define XFS_INO_AGBNO_BITS(mp)      (mp)->m_sb.sb_agblklog
def XFS_INO_AGBNO_BITS(mp):
	return readSU("struct xfs_mount", mp).m_sb.sb_agblklog

#1047 #define XFS_INO_AGINO_BITS(mp)      (mp)->m_agino_log
def XFS_INO_AGINO_BITS(mp):
	return readSU("struct xfs_mount", mp).m_agino_log

#1048 #define XFS_INO_AGNO_BITS(mp)       (mp)->m_agno_log
def XFS_INO_AGNO_BITS(mp):
	return readSU("struct xfs_mount", mp).m_agno_log

#1049 #define XFS_INO_BITS(mp)        \
#1050     XFS_INO_AGNO_BITS(mp) + XFS_INO_AGINO_BITS(mp)
def XFS_INO_BITS(mp):
	return XFS_INO_AGNO_BITS(mp) + XFS_INO_AGINO_BITS(mp)

#1051 #define XFS_INO_TO_AGNO(mp,i)       \
#1052     ((xfs_agnumber_t)((i) >> XFS_INO_AGINO_BITS(mp)))
def XFS_INO_TO_AGNO(mp, i):
	return (cast__xfs_agnumber_t(i >> XFS_INO_AGINO_BITS(mp)))


#1053 #define XFS_INO_TO_AGINO(mp,i)      \
#1054     ((xfs_agino_t)(i) & XFS_INO_MASK(XFS_INO_AGINO_BITS(mp)))
def XFS_INO_TO_AGINO(mp, i):
	return (cast__xfs_agino_t(i) & XFS_INO_MASK(XFS_INO_AGINO_BITS(mp)))


#1055 #define XFS_INO_TO_AGBNO(mp,i)      \
#1056     (((xfs_agblock_t)(i) >> XFS_INO_OFFSET_BITS(mp)) & \
#1057         XFS_INO_MASK(XFS_INO_AGBNO_BITS(mp)))
def XFS_INO_TO_AGBNO(mp, i):
	return ((cast__xfs_agblock_t(i) >> XFS_INO_OFFSET_BITS(mp)) &
			XFS_INO_MASK(XFS_INO_AGBNO_BITS(mp)))

#1058 #define XFS_INO_TO_OFFSET(mp,i)     \
#1059     ((int)(i) & XFS_INO_MASK(XFS_INO_OFFSET_BITS(mp)))
def XFS_INO_TO_OFFSET(mp, i):
	return ((int)(i) & XFS_INO_MASK(XFS_INO_OFFSET_BITS(mp)))




#1060 #define XFS_INO_TO_FSB(mp,i)        \
#1061     XFS_AGB_TO_FSB(mp, XFS_INO_TO_AGNO(mp,i), XFS_INO_TO_AGBNO(mp,i))
def XFS_INO_TO_FSB(mp, i):
	return XFS_AGB_TO_FSB(mp, XFS_INO_TO_AGNO(mp, i), XFS_INO_TO_AGBNO(mp, i))


#1062 #define XFS_AGINO_TO_INO(mp,a,i)    \
#1063     (((xfs_ino_t)(a) << XFS_INO_AGINO_BITS(mp)) | (i))
def XFS_AGINO_TO_INO(mp, a, i):
	return ((cast__xfs_ino_t(a) << XFS_INO_AGINO_BITS(mp)) | (i))

#1064 #define XFS_AGINO_TO_AGBNO(mp,i)    ((i) >> XFS_INO_OFFSET_BITS(mp))
def XFS_AGINO_TO_AGBNO(mp, i):
	return (i >> XFS_INO_OFFSET_BITS(mp))

#1065 #define XFS_AGINO_TO_OFFSET(mp,i)   \
#1066     ((i) & XFS_INO_MASK(XFS_INO_OFFSET_BITS(mp)))
def XFS_AGINO_TO_OFFSET(mp, i):
	return (i & XFS_INO_MASK(XFS_INO_OFFSET_BITS(mp)))

#1067 #define XFS_OFFBNO_TO_AGINO(mp,b,o) \
#1068     ((xfs_agino_t)(((b) << XFS_INO_OFFSET_BITS(mp)) | (o)))
def XFS_OFFBNO_TO_AGINO(mp, b, o):
	return cast__xfs_agino_t((b << XFS_INO_OFFSET_BITS(mp)) | o)

#define XFS_AGB_TO_FSB(mp,agno,agbno)   \
#  (((xfs_fsblock_t)(agno) << (mp)->m_sb.sb_agblklog) | (agbno))
def XFS_AGB_TO_FSB(mp, agno, agbno):
	return ((agno << mp.m_sb.sb_agblklog) | agbno)

#define XFS_FSB_TO_AGNO(mp,fsbno)       \
# ((xfs_agnumber_t)((fsbno) >> (mp)->m_sb.sb_agblklog))
def XFS_FSB_TO_AGNO(mp, fsbno):
	return cast__xfs_agnumber_t(fsbno >> mp.m_sb.sb_agblklog)
#define XFS_FSB_TO_AGBNO(mp,fsbno)      \
# ((xfs_agblock_t)((fsbno) & xfs_mask32lo((mp)->m_sb.sb_agblklog)))
def XFS_FSB_TO_AGBNO(mp, fsbno):
	return cast__xfs_agblock_t(fsbno & xfs_mask32lo(mp.m_sb.sb_agblklog))
#define XFS_AGB_TO_DADDR(mp,agno,agbno) \
# ((xfs_daddr_t)XFS_FSB_TO_BB(mp, (xfs_fsblock_t)(agno) * (mp)->m_sb.sb_agblocks + (agbno)))
def XFS_AGB_TO_DADDR(mp, agno, agbno):
	return cast__xfs_daddr_t(XFS_FSB_TO_BB(mp, agno * (mp.m_sb.sb_agblocks + agbno)))
#define XFS_AG_DADDR(mp,agno,d)         (XFS_AGB_TO_DADDR(mp, agno, 0) + (d))
def XFS_AG_DADDR(mp, agno, d):
	return (XFS_AGB_TO_DADDR(mp, agno, 0) + d)




#define agblock_to_bytes(x)     \
# ((uint64_t)(x) << mp->m_sb.sb_blocklog)
def agblock_to_bytes(mp, x):
	return (x << mp.m_sb.sb_blocklog)
#define agino_to_bytes(x)       \
# ((uint64_t)(x) << mp->m_sb.sb_inodelog)
def agino_to_bytes(mp, x):
	return (x << mp.m_sb.sb_inodelog)
#define agnumber_to_bytes(x)    \
# agblock_to_bytes((uint64_t)(x) * mp->m_sb.sb_agblocks)
def agnumber_to_bytes(mp, x):
	return agblock_to_bytes(mp, x * mp.m_sb.sb_agblocks)
#define daddr_to_bytes(x)       \
# ((uint64_t)(x) << BBSHIFT)
def daddr_to_bytes(mp, x):
	return (x << BBSHIFT)
#define fsblock_to_bytes(x)     \
# (agnumber_to_bytes(XFS_FSB_TO_AGNO(mp, (x))) + \
# agblock_to_bytes(XFS_FSB_TO_AGBNO(mp, (x))))
def fsblock_to_bytes(mp, x):
	return (agnumber_to_bytes(mp, XFS_FSB_TO_AGNO(mp, x)) +
			agblock_to_bytes(mp, XFS_FSB_TO_AGBNO(mp, x)))
#define ino_to_bytes(x)         \
# (agnumber_to_bytes(XFS_INO_TO_AGNO(mp, (x))) + \
# agino_to_bytes(XFS_INO_TO_AGINO(mp, (x))))
def ino_to_bytes(mp, x):
	return (agnumber_to_bytes(mp, XFS_INO_TO_AGNO(mp, x)) +
			agino_to_bytes(mp, XFS_INO_TO_AGINO(mp, x)))
#define inoidx_to_bytes(x)      \
# ((uint64_t)(x) << mp->m_sb.sb_inodelog)
def inoidx_to_bytes(mp, x):
	return (x << mp.m_sb.sb_inodelog)


try:
#	xfs_inode_operations = readSU(readSymbol("xfs_inode_operations"), "struct inode_operations")
	xfs_inode_operations = readSymbol("xfs_inode_operations")
except Exception as e:
	print("could not read 'xfs_inode_operations': {}".format(e))
	xfs_inode_operations = 0
try:
#	xfs_dir_inode_operations = readSU(readSymbol("xfs_dir_inode_operations"), "struct inode_operations")
	xfs_dir_inode_operations = readSymbol("xfs_dir_inode_operations")
except:
	print("could not read 'xfs_dir_inode_operations'")
	xfs_dir_inode_operations = 0
try:
#	xfs_dir_ci_inode_operations = readSU(readSymbol("xfs_dir_ci_inode_operations"), "struct inode_operations")
	xfs_dir_ci_inode_operations = readSymbol("xfs_dir_ci_inode_operations")
except:
	print("could not read 'xfs_dir_ci_inode_operations'")
	xfs_dir_ci_inode_operations = 0
try:
#	xfs_symlink_inode_operations = readSU(readSymbol("xfs_symlink_inode_operations"), "struct inode_operations")
	xfs_symlink_inode_operations = readSymbol("xfs_symlink_inode_operations")
except Exception as e:
	print("could not read 'xfs_symlink_inode_operations': {}".format(e))
	xfs_symlink_inode_operations = 0

try:
	xfs_file_operations = readSU(readSymbol("xfs_file_operations"), "struct file_operations")
	xfs_dir_file_operations = readSU(readSymbol("xfs_dir_file_operations"), "struct file_operations")
except:
	xfs_file_operations = 0
	xfs_dir_file_operations = 0

try:
	xfs_super_operations = readSU(readSymbol("xfs_super_operations"), "struct super_operations")
	xfs_address_space_operations = readSU(readSymbol("xfs_address_space_operations"), "struct address_space_operations")
#	xfs_quotactl_operations
#	xfs_export_operations
except:
	xfs_address_space_operations = 0
	xfs_super_operations = 0


def check_prune(struct_name, addr):
	global prune_list

	prune_key = "{}.0x{:016x}".format(struct_name, addr)

	try:
		prune_this = prune_list[prune_key]
	except:
		prune_this = False
		prune_list[prune_key] = True
	return prune_this


def show_uuid_be(addr):
	uuid = readSU("uuid_be", addr)
	for i in range(0, 16):
		print("{:02x}".format(uuid[i] & 0xff), end='')
		if (i == 3 or i == 5 or i == 7 or i == 9):
			print("-", end='')
	print("")

#def from_type_bytes(mp, from_type, val):
#	if from_type == "agblock" or from_type == "agbno":

def xfs_whatever_is_xfs_sb(addr):
	try:
		xfs_sb = readSU("struct xfs_sb", addr)
		if xfs_sb.sb_magicnum == XFS_SB_MAGIC:
			return True
	except:
		return False
def xfs_whatever_is_xfs_mount(addr):
	try:
		xfs_mount = readSU("struct xfs_mount", addr)

#		ail = xfs_mount.m_ail
#		if ail.m_sb != xfs_mount.m_sb:
#			return False
		return xfs_whatever_is_xfs_sb(xfs_mount.m_sb)
	except:
		return False
def xfs_whatever_is_sb(addr):
	try:
		sb = readSU("struct super_block", addr)
		return xfs_whatever_is_xfs_mount(sb.s_fs_info)
	except:
		return False
def xfs_whatever_is_xfs_trans(addr):
	try:
		tp = readSU("struct xfs_trans", addr)
		if tp.t_magic == XFS_TRANS_HEADER_MAGIC:
			return True
	except:
		return False
	return False
def xfs_whatever_is_bmap(addr):
	try:
		btb = readSU("struct xfs_btree_block", addr)
		if btb.bb_magic == htonl(XFS_BMAP_MAGIC):
			return True
	except:
		return False
	return False
def xfs_whatever_is_bmap_crc(addr):
	try:
		btb = readSU("struct xfs_btree_block", addr)
		if btb.bb_magic == htonl(XFS_BMAP_CRC_MAGIC):
			return True
	except:
		return False
	return False
def xfs_whatever_is_xfs_buftarg(addr):
	try:
		xbt = readSU("struct xfs_buftarg", addr)
		if xbt.bt_mount and xfs_whatever_is_xfs_mount(xbt.bt_mount):
			return True
	except:
		pass
	return False
def xfs_whatever_is_xfs_buf(addr):
	try:
		xbf = readSU("struct xfs_buf", addr)
		if xfs_whatever_is_xfs_trans(xbf.b_transp):
			return True
		if xbf.b_target and xfs_whatever_is_xfs_buftarg(xbf.b_target):
			return True
	except:
		pass
	return False
def xfs_whatever_is_xfs_perag(addr):
	try:
		pag = readSU("struct xfs_perag", addr)
		return xfs_whatever_is_xfs_mount(pag.pag_mount)
	except:
		return False
def xfs_whatever_is_xfs_inode(addr):
	try:
		xi = readSU("struct xfs_inode", addr)
	except:
		return False

	try:
		i_op = xi.i_vnode.i_op
		if i_op == 0:
			return False
		if i_op == xfs_inode_operations:
			print("xfs_whatever_is_xfs_inode i_op {:016x} is an xfs_inode_operations: {:016x}".format(i_op, xfs_inode_operations))
			return True
		if i_op == xfs_dir_inode_operations:
#			print("xfs_whatever_is_xfs_inode i_op {:016x} is an xfs_dir_inode_operations {:016x}".format(i_op, xfs_dir_inode_operations))
			return True
		if i_op == xfs_dir_ci_inode_operations or i_op == xfs_symlink_inode_operations:
#			print("xfs_whatever_is_xfs_inode i_op is an xfs_dir_ci_inode_operations or xfs_symlink_inode_operations")
			return True
#		print("got i_op (0{:016x}, but it doesn't match some stuff".format(i_op)) # hmm. what else would it be?
	except:
		print("got exceptions trying to read xi.i_vnode.*")
		pass
#	print("still checking")
	try:
		if xfs_whatever_is_xfs_mount(xi.i_mount):
			print("it's an xfs_mount")
			return True
	except:
		pass
	return False
def xfs_whatever_is_inode(addr):
	inode = readSU("struct inode", addr)
	sb = inode.i_sb

	if not xfs_whatever_is_sb(sb):
		return False
	try:
		xi = readSU("struct xfs_inode", container_of(addr, "struct xfs_inode", "i_vnode"))
	except:
		return False
	return xfs_whatever_is_xfs_inode(xi)
def xfs_whatever_is_xlog(addr):
	xlog = readSU("struct xlog", addr)
	try:
		ail = xlog.l_ailp
		xfs_mount = xlog.l_mp

		if ail.xa_mount != xlog.l_mp:
			return False

		if xfs_mount.m_log != xlog:
			return False
	except:
		return False
	return xfs_whatever_is_xfs_mount(xfs_mount)

def xfs_whatever_is_cil(addr):
	try:
		cil = readSU("struct xfs_cil", addr)

		xc_ctx = cil.xc_ctx
		if xc_ctx.cil != cil:
			return False

	except:
		return False
	return xfs_whatever_is_xlog(cil.xc_log)

def xfs_whatever_is_xfs_buftarg(addr):
	try:
		bt = readSU("struct xfs_buftarg", addr)

		if not xfs_whatever_is_xfs_mount(bt.bt_mount):
			return False

#crash> xfs_buftarg.bt_meta_sectormask,bt_meta_sectorsize,bt_logical_sectorsize,bt_logical_sectormask 0xffff9de6629c3700
#  bt_meta_sectormask = 0x1ff
#  bt_meta_sectorsize = 0x200
#  bt_logical_sectorsize = 0x200
#  bt_logical_sectormask = 0x1ff
#crash> px (0x200 & 0x1ff)
#$1 = 0x0
#crash> px (0x200 ^ 0x1ff)
#$2 = 0x3ff
#crash> px (0x200 | 0x1ff)
#$3 = 0x3ff
		ss1 = bt.bt_meta_sectorsize
		sm1 = bt.bt_meta_sectormask
		ss2 = bt.bt_logical_sectorsize
		sm2 = bt.bt_logical_sectormask

		if (ss1 & sm1 != 0) or (ss1 ^ sm1 != ss1 | sm1):
			return False

		if (ss1 & sm1 == 0) and (ss1 ^ sm1 == ss1 | sm1) and (ss1 == sm1 + 1) and \
			(ss2 & sm2 == 0) and (ss2 ^ sm2 == ss2 | sm2) and (ss2 == sm2 + 2):
				return True

		# pretty tenuous, but possible... anything further we can check?
		return True
	except:
		return False
	return False


def xfs_whatever_id(addr):
	if xfs_whatever_is_xfs_mount(addr):
		return "xfs_mount"
	if xfs_whatever_is_xfs_sb(addr):
		return "xfs_sb"
	if xfs_whatever_is_sb(addr):
		return "super_block"
	if xfs_whatever_is_xfs_buf(addr):
		return "xfs_buf"
	if xfs_whatever_is_xfs_inode(addr):
		return "xfs_inode"
	if xfs_whatever_is_xfs_trans(addr):
		return "xfs_trans"
	if xfs_whatever_is_inode(addr):
		return "inode"
	if xfs_whatever_is_bmap(addr):
		return "xfs_bmap"
	if xfs_whatever_is_bmap_crc(addr):
		return "xfs_bmap"
	if xfs_whatever_is_xlog(addr):
		return "xlog"
	if xfs_whatever_is_cil(addr):
		return "xfs_cil"
	if xfs_whatever_is_xfs_perag(addr):
		return "xfs_perag"
	if xfs_whatever_is_xfs_buftarg(addr):
		return "xfs_buftarg"
	return "UNKNOWN"

def xfs_mount_from_xfs_sb(addr):
	try:
		xfs_sb = readSU("struct xfs_sb", addr)
		return readSU("struct xfs_mount", container_of(xfs_sb, "struct xfs_mount", "m_sb"))
	except:
		return 0
def xfs_mount_from_sb(addr):
	try:
		sb = readSU("struct super_block", addr)
		return readSU("struct xfs_mount", sb.s_fs_info)
	except:
		return 0
def xfs_mount_from_xfs_buf(addr):
	try:
		return readSU("struct xfs_buf", addr).b_transp.t_mountp
	except:
		pass
	try:
		return readSU("struct xfs_buf", addr).b_pag.pag_mount
	except:
		return 0
	return 0
def xfs_mount_from_xfs_inode(addr):
	try:
		return readSU("struct xfs_inode", addr).i_mount
	except:
		return 0
def xfs_mount_from_xfs_inode(addr):
	try:
		return readSU("struct xfs_inode", addr).i_mount
	except:
		return 0
def xfs_mount_from_inode(addr):
	try:
		xi = readSU("struct xfs_inode", container_of(addr, "struct xfs_inode", "i_vnode"))
	except:
		return 0
	return xfs_mount_from_xfs_inode(xi)
def xfs_mount_from_xlog(addr):
	try:
		xlog = readSU("struct xlog", addr)
#		print("checking xlog {:016x}".format(xlog))
		return xlog.l_mp
	except:
		return 0
def xfs_mount_from_xfs_cil(addr):
	try:
		cil = readSU("struct xfs_cil", addr)
		xlog = cil.xc_log
	except:
		return 0
	return xfs_mount_from_xlog(xlog)

def xfs_mount_from_whatever(id, addr):
	if id == "xfs_mount":
		return readSU("struct xfs_mount", addr)
	if id == "xfs_sb":
		return xfs_mount_from_xfs_sb(addr)
	if id == "super_block":
		return xfs_mount_from_sb(addr)
	if id == "xfs_buf":
		return xfs_mount_from_xfs_buf(addr)
	if id == "xfs_inode":
		return xfs_mount_from_xfs_inode(addr)
	if id == "inode":
		return xfs_mount_from_inode(addr)
	if id == "xlog":
		return xfs_mount_from_xlog(addr)
	if id == "xfs_cil":
		return xfs_mount_from_xfs_cil(addr)
	print("0x{:016x} is Unknown".format(addr))
	return None

agblock_strings = ("agblock", "agbno")
agino_strings = ("agino", "aginode")
agnumber_strings = ("agnumbrer", "agno")
bboff_strings = ("bboff", "daddroff")
blkoff_strings = ("blkoff", "fsboff", "agboff")
byte_strings = ("byte", "fsbyte")
daddr_strings = ("daddr", "bb")
fsblock_strings = ("fsblock", "fsb", "fsbno")
ino_strings = ("ino", "inode")
inoidx_strings = ("inoidx", "offset")
inooff_strings = ("inooff", "inodeoff")

def do_convert_from(mp, from_type, val):
	mp = readSU("struct xfs_mount", mp)
#	bytes = from_type_bytes(mp, from_type, val)

	if from_type in agblock_strings:
#  M(AGNUMBER)|M(BBOFF)|M(BLKOFF)|M(INOIDX)|M(INOOFF)
		return agblock_to_bytes(mp, val);
	elif from_type in agino_strings:
# M(AGNUMBER)|M(INOOFF)
		return agino_to_bytes(mp, val)
	elif from_type in agnumber_strings:
#  M(AGBLOCK)|M(AGINO)|M(BBOFF)|M(BLKOFF)|M(INOIDX)|M(INOOFF)
		return agnumber_to_bytes(mp, val)

#		print("from agno {} to {} bytes".format(val, bytes))
#		if to_type in agblock_strings:
#			return xfs_daddr_to_agbno(mp, bytes >> BBSHIFT)
#		elif to_type in agino_strings:
#			print("to AGINO: {}".format(((bytes >> mp.m_sb.sb_inodelog) % (mp.m_sb.sb_agblocks << mp.m_sb.sb_inopblog))))
#			print("... {} bytes >> something ({}) = {}".format(bytes, mp.m_sb.sb_inodelog, (bytes >> mp.m_sb.sb_inodelog)))
#			print("(mp.m_sb.sb_agblocks ({}) << mp.m_sb.sb_inopblog ({})) = {}".format(mp.m_sb.sb_agblocks, mp.m_sb.sb_inopblog, (mp.m_sb.sb_agblocks << mp.m_sb.sb_inopblog)))
#			return ((bytes >> mp.m_sb.sb_inodelog) %
#				(mp.m_sb.sb_agblocks << mp.m_sb.sb_inopblog))
	elif from_type in bboff_strings:
# M(AGBLOCK)|M(AGNUMBER)|M(DADDR)|M(FSBLOCK)
		return val
	elif from_type in blkoff_strings:
# M(AGBLOCK)|M(AGNUMBER)|M(FSBLOCK),
		return val
	elif from_type in byte_strings:
# nothing?
		return val
	elif from_type in daddr_strings:
# BBOFF
		ret = (daddr_to_bytes(mp, val) & BBMASK)
		print("from daddr {} - bytes: {}".format(val, ret))
		return (daddr_to_bytes(mp, val) & BBMASK)
	elif from_type in fsblock_strings:
# M(BBOFF)|M(BLKOFF)|M(INOIDX
		return fsblock_to_bytes(mp, val)
	elif from_type in ino_strings:
# INOOFF
		return ino_to_bytes(mp, val)
#		bytes = ino_to_bytes(mp, val)
#		print("from ino_strings {} to {} bytes".format(val, bytes))
#		if to_type in inooff_strings:
#			print("converting TO INOOFF")
#			return (bytes & (mp.m_sb.sb_inodesize - 1))
#		elif to_type in daddr_strings:
#			print("converting TO DADDR")
#			return (bytes >> BBSHIFT)
	elif from_type in inoidx_strings:
# M(AGBLOCK)|M(AGNUMBER)|M(FSBLOCK)|M(INOOFF)
		return inoidx_to_bytes(mp, val)
	elif from_type in inooff_strings:
# M(AGBLOCK)|M(AGINO)|M(AGNUMBER)|M(FSBLOCK)|M(INO)|M(INOIDX
		return val
	else:
		print("Error: unable to process 'from' type '{}'".format(from_type))
		return None
#	print("unable to convert to type '{}'".format(to_type))
	print("unable to convert from type '{}'".format(from_type))
	return None

def do_convert_to(mp, bytes, to_type):
	mp = readSU("struct xfs_mount", mp)
#	bytes = from_type_bytes(mp, from_type, val)

	if to_type in agnumber_strings:
		return xfs_daddr_to_agno(mp, bytes >> BBSHIFT)

	elif to_type in bboff_strings:
		return (bytes & BBMASK)

	elif to_type in blkoff_strings:
		return (bytes & mp.m_blockmask)

	elif to_type in inoidx_strings:
		return (bytes >> mp.m_sb.sb_inodelog) & (mp.m_sb.sb_inopblock - 1)

	elif to_type in inooff_strings:
#		print("converting TO INOOFF")
		return (bytes & (mp.m_sb.sb_inodesize - 1))

	elif to_type in agblock_strings:
		return xfs_daddr_to_agbno(mp, bytes >> BBSHIFT)

	elif to_type in agino_strings:
#		print("to AGINO: {}".format(((bytes >> mp.m_sb.sb_inodelog) % (mp.m_sb.sb_agblocks << mp.m_sb.sb_inopblog))))
#		print("... {} bytes >> something ({}) = {}".format(bytes, mp.m_sb.sb_inodelog, (bytes >> mp.m_sb.sb_inodelog)))
#		print("(mp.m_sb.sb_agblocks ({}) << mp.m_sb.sb_inopblog ({})) = {}".format(mp.m_sb.sb_agblocks, mp.m_sb.sb_inopblog, (mp.m_sb.sb_agblocks << mp.m_sb.sb_inopblog)))
		return ((bytes >> mp.m_sb.sb_inodelog) %
			(mp.m_sb.sb_agblocks << mp.m_sb.sb_inopblog))

	elif to_type in fsblock_strings:
		return XFS_DADDR_TO_FSB(mp, bytes >> BBSHIFT)

	elif to_type in daddr_strings:
		return (bytes >> BBSHIFT)

	elif to_type in ino_strings:
#		return (bytes & (mp.m_sb.sb_inodesize - 1))
		return XFS_AGINO_TO_INO(mp, xfs_daddr_to_agno(mp, bytes >> BBSHIFT),
				(bytes >> mp.m_sb.sb_inodelog) % (mp.m_sb.sb_agblocks << mp.m_sb.sb_inopblog))
	else:
		print("Unable to convert to '{}'".format(to_type))
		return None




def do_convert(mp, from_type, val, to_type):
	mp = readSU("struct xfs_mount", mp)
#	bytes = from_type_bytes(mp, from_type, val)

	if from_type in agblock_strings:
#  M(AGNUMBER)|M(BBOFF)|M(BLKOFF)|M(INOIDX)|M(INOOFF)
		bytes = agblock_to_bytes(mp, val);
		if to_type in agnumber_strings:
			return xfs_daddr_to_agno(mp, bytes >> BBSHIFT)
		elif to_type in bboff_strings:
			return (bytes & BBMASK)
		elif to_type in blkoff_strings:
			return (bytes & mp.m_blockmask)
		elif to_type in inoidx_strings:
			return (bytes >> mp.m_sb.sb_inodelog) & (mp.m_sb.sb_inopblock - 1)
		elif to_type in inooff_strings:
			return (bytes & (mp.m_sb.sb_inodesize - 1))
	elif from_type in agino_strings:
# M(AGNUMBER)|M(INOOFF)
		bytes = agino_to_bytes(mp, val)
		if to_type in agnumber_strings:
			return xfs_daddr_to_agno(mp, bytes >> BBSHIFT)
		elif to_type in inooff_strings:
			return (bytes & (mp.m_sb.sb_inodesize - 1))
	elif from_type in agnumber_strings:
#  M(AGBLOCK)|M(AGINO)|M(BBOFF)|M(BLKOFF)|M(INOIDX)|M(INOOFF)
		bytes = agnumber_to_bytes(mp, val)
		print("from agno {} to {} bytes".format(val, bytes))
		if to_type in agblock_strings:
			return xfs_daddr_to_agbno(mp, bytes >> BBSHIFT)
		elif to_type in agino_strings:
			print("to AGINO: {}".format(((bytes >> mp.m_sb.sb_inodelog) % (mp.m_sb.sb_agblocks << mp.m_sb.sb_inopblog))))
			print("... {} bytes >> something ({}) = {}".format(bytes, mp.m_sb.sb_inodelog, (bytes >> mp.m_sb.sb_inodelog)))
			print("(mp.m_sb.sb_agblocks ({}) << mp.m_sb.sb_inopblog ({})) = {}".format(mp.m_sb.sb_agblocks, mp.m_sb.sb_inopblog, (mp.m_sb.sb_agblocks << mp.m_sb.sb_inopblog)))
			return ((bytes >> mp.m_sb.sb_inodelog) %
				(mp.m_sb.sb_agblocks << mp.m_sb.sb_inopblog))
		elif to_type in bboff_strings:
			return (bytes & BBMASK)
		elif to_type in blkoff_strings:
			return bytes & mp.m_blockmask
		elif to_type in inoidx_strings:
			return ((bytes >> mp.m_sb.sb_inodelog) & (mp.m_sb.sb_inopblock - 1))
		elif to_type in inooff_strings:
			return (bytes & (mp.m_sb.sb_inodesize - 1))
	elif from_type in bboff_strings:
# M(AGBLOCK)|M(AGNUMBER)|M(DADDR)|M(FSBLOCK)
		bytes = val
		if to_type in agblock_strings:
			return xfs_daddr_to_agbno(mp, bytes >> BBSHIFT)
		if to_type in agnumber_strings:
			return xfs_daddr_to_agno(mp, bytes >> BBSHIFT)
	elif from_type in blkoff_strings:
# M(AGBLOCK)|M(AGNUMBER)|M(FSBLOCK),
		bytes = val
		if to_type in agblock_strings:
			return xfs_daddr_to_agbno(mp, bytes >> BBSHIFT)
		elif to_type in agnumber_strings:
			return xfs_daddr_to_agno(mp, bytes >> BBSHIFT)
		elif to_type in fsblock_strings:
			return XFS_DADDR_TO_FSB(mp, bytes >> BBSHIFT)
	elif from_type in byte_strings:
# nothing?
		bytes = val
		return bytes
	elif from_type in daddr_strings:
# BBOFF
		bytes = daddr_to_bytes(mp, val)
		return (bytes & BBMASK)
	elif from_type in fsblock_strings:
# M(BBOFF)|M(BLKOFF)|M(INOIDX
		bytes = fsblock_to_bytes(mp, val)
		if to_type in bboff_strings:
			return (bytes & BBMASK)
		elif to_type in blkoff_strings:
			return (bytes & mp.m_blockmask)
		elif to_type in inoidx_strings:
			return ((bytes >> mp.m_sb.sb_inodelog) & (mp.m_sb.sb_inopblock - 1))
	elif from_type in ino_strings:
# INOOFF
		bytes = ino_to_bytes(mp, val)
		print("from ino_strings {} to {} bytes".format(val, bytes))
		if to_type in inooff_strings:
			print("converting TO INOOFF")
			return (bytes & (mp.m_sb.sb_inodesize - 1))
		elif to_type in daddr_strings:
			print("converting TO DADDR")
			return (bytes >> BBSHIFT)
	elif from_type in inoidx_strings:
# M(AGBLOCK)|M(AGNUMBER)|M(FSBLOCK)|M(INOOFF)
		bytes = inoidx_to_bytes(mp, val)
		if to_type in agblock_strings:
			return xfs_daddr_to_agbno(mp, bytes >> BBSHIFT)
		elif to_type in agnumber_strings:
			return xfs_daddr_to_agno(mp, bytes >> BBSHIFT)
		elif to_type in fsblock_strings:
			return XFS_DADDR_TO_FSB(mp, bytes >> BBSHIFT)
		elif to_type in inooff_strings:
			return (bytes & (mp.m_sb.sb_inodesize - 1))
	elif from_type in inooff_strings:
# M(AGBLOCK)|M(AGINO)|M(AGNUMBER)|M(FSBLOCK)|M(INO)|M(INOIDX
		bytes = val
		if to_type in agblock_strings:
			return xfs_daddr_to_agbno(mp, bytes >> BBSHIFT)
		elif to_type in agino_strings:
			return ((bytes >> mp.m_sb.sb_inodelog) %
				(mp.m_sb.sb_agblocks << mp.m_sb.sb_inopblog))
		elif to_type in agnumber_strings:
			return xfs_daddr_to_agno(mp, bytes >> BBSHIFT)
		elif to_type in fsblock_strings:
			return XFS_DADDR_TO_FSB(mp, bytes >> BBSHIFT)
		elif to_type in ino_strings:
#			return (bytes & (mp.m_sb.sb_inodesize - 1))
			return XFS_AGINO_TO_INO(mp, xfs_daddr_to_agno(mp, bytes >> BBSHIFT),
					(bytes >> mp.m_sb.sb_inodelog) % (pm.m_sb.sb_agblocks << mp.m_sb.sb_inopblog))
	else:
		print("Error: unable to process 'from' type '{}'".format(from_type))
		return None
	print("unable to convert to type '{}'".format(to_type))
	return None

def convert_cmd(args):
	xfs_whatever_addr = get_arg_value(args[0])
	print("xfs_whatever address is 0x{:016x}".format(xfs_whatever_addr))

	id = xfs_whatever_id(xfs_whatever_addr)

	mp = readSU("struct xfs_mount", xfs_mount_from_whatever(id, xfs_whatever_addr))
	if mp == None:
		print("Unable to determine an xfs_mount from 0x{:016x}".format(xfs_whatever_addr))
		return

	args = args[1:]

	if len(args) & 1 == 0:
		print("bad argument count ({}) to convert, expected '[source_type value]+ target_type'".format(len(args)))
		print("args: {}".format(args))
		return

	target_type = args[len(args) - 1]

	print("target_type: {}".format(target_type))

	bytes = 0
#	for i in range(0, (len(args) - 1) / 2):
	i = 0
	while i < len(args) - 1:
		from_type = args[i]
		to_type = args[-1]
		addr = args[i + 1]
#	for i in range(0, (len(args) - 1) / 2):
#		ret = do_convert_from(mp, args[i*2], get_arg_value(args[i*2 + 1]))
#		print("want to convert addr '{}' from '{}' to '{}'".format(args[i+1], args[i], args[-1]))
		print("want to convert addr '{}' from '{}' to '{}'".format(addr, from_type, to_type))
#		ret = do_convert_from(mp, args[i], get_arg_value(args[i + 1]))
		ret = do_convert_from(mp, from_type, get_arg_value(addr))
		if not ret is None:
			bytes += ret
		i += 2

	print("result of from_types: {}".format(bytes))

	ret = do_convert_to(mp, bytes, target_type)

	if ret is not None:
		print("0x{:x} ({})".format(ret, ret))

	return

	from_type = args[1]
	val = get_arg_value(args[2])
#	from_type = args[3]
	to_type = args[4]

	print("from_type: {}, val: {}, to_type: {}".format(from_type, val, to_type))

	ret = do_convert(mp, from_type, val, to_type)

	if ret is not None:
		print("0x{:x} ({})".format(ret, ret))


def show_struct_member_simple(struct, member_name, ilvl=0):
	try:
		print("{}.{}: {}".format(indent_str(ilvl), member_name, struct.Eval(member_name)))
	except:
		pass

def show_struct_member_simple_nonzero(struct, member_name, ilvl=0):
	try:
		if struct.Eval(member_name):
			print("{}.{}: {}".format(indent_str(ilvl), member_name, struct.Eval(member_name)))
	except:
		pass

def print_struct_ptr(addr, struct_type, ilvl=0, member_name="", todo=False):
	if member_name == "":
		print("{}(struct {} *)0x{:016x}{}".format(indent_str(ilvl), struct_type, addr,
			" - TODO" if todo==True else ""))
	else:
		print("{}.{}(struct {} *)0x{:016x}{}".format(indent_str(ilvl),
			member_name, struct_type, addr,
			" - TODO" if todo==True else ""))

def show_struct_member_TODO(addr, member_name="", member_type="", ilvl=0):
	if not member_name=="" and not member_type=="":
		print("{}.{} (struct {} *)0x{:016x} - TODO".format(indent_str(ilvl), member_name, member_type, addr))


def show_xlog_ticket(addr, ilvl=0):
	print_struct_ptr(addr, "xlog_ticket", ilvl=ilvl)

	if not check_prune("xlog_ticket", addr):
		try:
			tic = readSU("struct xlog_ticket", addr);
			print_struct_ptr(addr, "xlog_ticket", ilvl=ilvl, todo=True)
#			print("{}TODO".format(indent_str(ilvl)))
		except:
			pass

def get_sb_mountpoints(addr, ilvl=0):
	try:
		sb = readSU("struct super_block", addr)
		s_mounts = readSUListFromHead(sb.s_mounts, "mnt_instance", "struct mount")
		for mount in s_mounts:
			print("{}(struct mount *)0x{:016x} - {}   {}".format(indent_str(ilvl), mount, mount.mnt_devname, get_pathname(mount.mnt_mountpoint, mount.mnt)))
			print("{}.mnt_ns: struct mnt_namespace *)0x{:016x}, .mnt_mp: (struct mountpoint *)0x{:016x}".format(indent_str(ilvl+1), mount.mnt_ns, mount.mnt_mp))
	except:
		pass


def show_xfs_cil_ctx(addr, ilvl=0):
	print_struct_ptr(addr, "xfs_cil_ctx", ilvl)
#	print("{}(struct xfs_cil_ctx *)0x{:016x}".format(indent_str(ilvl), addr))

	if not check_prune("xfs_cil_ctx", addr):
		try:
			ctx = readSU("struct xfs_cil_ctx", addr)
			print("{}.cil: ".format(indent_str(ilvl)), end='')
			show_xfs_cil(ctx.cil, ilvl=0)

			show_struct_member_simple(ctx, "sequence", ilvl=ilvl)
			show_struct_member_simple(ctx, "start_lsn", ilvl=ilvl)
			show_struct_member_simple(ctx, "commit_lsn", ilvl=ilvl)
			show_struct_member_simple(ctx, "nvecs", ilvl=ilvl)
			show_struct_member_simple(ctx, "space_used", ilvl=ilvl)

			show_xlog_ticket(ctx.ticket, ilvl=ilvl+1)
		except:
			pass

def show_xfs_cil(addr, ilvl=0):
	print("{}(struct xfs_cil *)0x{:016x}".format(indent_str(ilvl), addr))


	# list xc_cil

	if not check_prune("xfs_cil", addr):
		# show xfs_cil stuff
		try:
			cil = readSU("struct xfs_cil", addr)
			print("{}.xc_push_seq: {}".format(indent_str(ilvl), cil.xc_push_seq))
			try:
				print("{}.xc_current_seq: {}".format(indent_str(ilvl), cil.xc_current_seq))
			except:
				pass

			show_xlog(cil.xc_log, ilvl=ilvl+1)
			print("{}more TODO".format(indent_str(ilvl)))
		except:
			pass


XFS_LOG_ITEM_TYPES_C = '''
#define XFS_LI_EFI              0x1236
#define XFS_LI_EFD              0x1237
#define XFS_LI_IUNLINK          0x1238
#define XFS_LI_INODE            0x123b  /* aligned ino chunks, var-size ibufs */
#define XFS_LI_BUF              0x123c  /* v2 bufs, variable sized inode bufs */
#define XFS_LI_DQUOT            0x123d
#define XFS_LI_QUOTAOFF         0x123e
#define XFS_LI_ICREATE          0x123f
'''
XFS_LOG_ITEM_TYPES = CDefine(XFS_LOG_ITEM_TYPES_C)
XFS_ILOG_FLAGS_C = '''
#define XFS_ILOG_CORE   0x001   /* log standard inode fields */
#define XFS_ILOG_DDATA  0x002   /* log i_df.if_data */
#define XFS_ILOG_DEXT   0x004   /* log i_df.if_extents */
#define XFS_ILOG_DBROOT 0x008   /* log i_df.i_broot */
#define XFS_ILOG_DEV    0x010   /* log the dev field */
#define XFS_ILOG_UUID   0x020   /* added long ago, but never used */
#define XFS_ILOG_ADATA  0x040   /* log i_af.if_data */
#define XFS_ILOG_AEXT   0x080   /* log i_af.if_extents */
#define XFS_ILOG_ABROOT 0x100   /* log i_af.i_broot */
#define XFS_ILOG_DOWNER 0x200   /* change the data fork owner on replay */
#define XFS_ILOG_AOWNER 0x400   /* change the attr fork owner on replay */
#define XFS_ILOG_TIMESTAMP      0x4000
'''
XFS_ILOG_FLAGS = CDefine(XFS_ILOG_FLAGS_C)

def flags_to_string(flags, strings):
	result = []
	for name, val in strings.items():
		if flags & val != 0:
			result.append(name)
			flags = flags & ~val
	if flags:
		result.append("0x{:x}".format(flags))
	return "|".join(result)
def flag_bits_to_string(flags, strings):
	result = []
	for name, val in strings.items():
		if flags & (1 << val) != 0:
			result.append(name)
			flags = flags & ~(1 << val)
	if flags:
		result.append("0x{:x}".format(flags))
	return "|".join(result)

def defines_to_string(match_val, strings):
	for name, val in strings.items():
		if match_val == val:
			return name
	return "UNKNOWN"

def show_xfs_ail(addr, ilvl=0):
	print("{}(struct xfs_ail *)0x{:016x}".format(indent_str(ilvl), addr))

	if not check_prune("xfs_ail", addr):
		try:
			ail = readSU("struct xfs_ail", addr)

			try: # xa_ail removed after kernel version ...?...
				ail_list = readSUListFromHead(ail.xa_ail, "li_ail", "struct xfs_log_item", maxel=10000000)
				print("{}entries in ail: {}".format(indent_str(ilvl), len(ail_list)))

				log_item_type_stats = {}
				inode_log_item_inodes = {}
				i = 0
				for li in ail_list:
					log_item_type = defines_to_string(li.li_type, XFS_LOG_ITEM_TYPES)
#					log_item_type_stats[log_item_type] = log_item_type_stats[log_item_type] + 1

					if i < 1000000:
						print("{}(struct xfs_log_item *)0x{:016x} - type: {}".format(indent_str(ilvl+1), li, log_item_type))


					if log_item_type == "XFS_LI_INODE":
						xfs_inode_log_item = readSU("struct xfs_inode_log_item", container_of(li, "struct xfs_inode_log_item", "ili_item"))

						if i < 1000000:
#							if log_item_type == "XFS_LI_INODE":
#							inode_log_item_inodes[xfs_inode_log_item] = inode_log_item_inodes[xfs_inode_log_item] = 1
							inode_log_item_inodes[Addr(xfs_inode_log_item.ili_inode.i_vnode)] = inode_log_item_inodes[Addr(xfs_inode_log_item.ili_inode.i_vnode)] = 1
							print("{}(struct xfs_inode_log_item *)0x{:016x}".format(indent_str(ilvl+2), xfs_inode_log_item))

							print("{}(struct inode *)0x{:016x}".format(indent_str(ilvl+2), xfs_inode_log_item.ili_inode.i_vnode))
							if xfs_inode_log_item.ili_last_fields:
								print("{}ili_last_fields: {}".format(indent_str(ilvl+2), flags_to_string(xfs_inode_log_item.ili_last_fields, XFS_ILOG_FLAGS)))
							if xfs_inode_log_item.ili_fields:
								print("{}ili_fields: {}".format(indent_str(ilvl+2), flags_to_string(xfs_inode_log_item.ili_fields, XFS_ILOG_FLAGS)))
							if xfs_inode_log_item.ili_fsync_fields:
								print("{}ili_fsync_fields: {}".format(indent_str(ilvl+2), flags_to_string(xfs_inode_log_item.ili_fsync_fields, XFS_ILOG_FLAGS)))


#					else if log_item_type == "XFS_LI_BUF":
#						xfs_buf_log_item = readSU("struct xfs_buf_log_item", container_of(li, "struct xfs_buf_log_item", "bli_item"))


					i = i + 1

				try:
#					if len(log_item_type_stats):
#						for lit in log_item_type_stats:
#							print("log_item_type_stats[{}] - {}".format(lit, log_item_type_stats[lit]))
					if len(inode_log_item_inodes):
						for inode in inode_log_item_inodes:
							print("inode log_item inode 0x{:016x} - {}".format(inode, inode_log_item_inodes[inode]))
				except:
					print("oops")
					pass




			except:
				pass
		except:
			pass


def show_xlog(addr, ilvl=0):
	print("{}(struct xlog *)0x{:016x}".format(indent_str(ilvl), addr))

	if not check_prune("xlog", addr):

		try:
			xlog = readSU("struct xlog", addr)

			show_xfs_mount(xlog.l_mp)

#			print("{}what info to show for xlog?".format(indent_str(ilvl)))
			cilp = xlog.l_cilp
			if cilp:
				show_xfs_cil(cilp, ilvl=ilvl+1)
			show_xfs_buf(xlog.l_xbuf, ilvl=ilvl+1)
#			show_xfs_buftarg # TODO
			show_struct_member_TODO(xlog.l_targ, member_name="l_targ", member_type="xfs_buftarg", ilvl=ilvl)

		except:
			pass

def show_xfs_info(addr, ilvl=0):
	print("{}(struct xfs_mount *)0x{:016x}".format(indent_str(ilvl), addr))

	if check_prune("xfs_info", addr):
		return

	xfs_mount = readSU("struct xfs_mount", addr)
	sbp = xfs_mount.m_sb

	print("{}(struct xfs_sb *)0x{:016x}".format(indent_str(ilvl), sbp))
	print("{}(struct xfs_ail *)0x{:016x}".format(indent_str(ilvl), xfs_mount.m_ail))
	show_xfs_ail(xfs_mount.m_ail, ilvl=ilvl+1)

	print("{}(struct super_block *)0x{:016x}".format(indent_str(ilvl), xfs_mount.m_super))

	get_sb_mountpoints(xfs_mount.m_super, ilvl=ilvl+1)


#	fs_size_string = val_to_units_string(sbp.sb_dblocks * sbp.sb_blocksize, 1024);
#	print("{}filesystem size: {}".format(indent_str(ilvl), sbp.sb_agcount * sbp.sb_agblocks * sbp.sb_blocksize))
#	print("{}filesystem size: {} ({})".format(indent_str(ilvl), sbp.sb_dblocks * sbp.sb_blocksize, fs_size_string))

	dblocks = sbp.sb_dblocks
	fdblocks = sbp.sb_fdblocks
	blocksize = sbp.sb_blocksize
	pct = (dblocks - fdblocks) * 100 / dblocks
	print("{}.sb_blocksize: {}, .sb_dblocks: {} ({}), .sb_fdblocks: {} ({}) - {:.3f}% in-use".format(
		indent_str(ilvl+1), blocksize,
		dblocks, val_to_units_string(dblocks * blocksize, 1024),
		fdblocks, val_to_units_string(fdblocks * blocksize, 1024), pct))
	print("{}.sb_icount: {}, .sb_ifree: {} - {:.3f}% in-use".format(
		indent_str(ilvl+1), sbp.sb_icount, sbp.sb_ifree, (sbp.sb_icount - sbp.sb_ifree) * 100 / sbp.sb_icount))

	print("super block version {}".format(XFS_SB_VERSION_NUM(sbp)))
	if sbp.sb_inprogress:
		print("***** WARNING: superblock sb_inprogress flag is set: {} *****".format(sbp.sb_inprogress))

#meta-data=/dev/mapper/vgapps-lvapps isize=256    agcount=9, agsize=16377600 blks
#         =                       sectsz=512   attr=2, projid32bit=1
#         =                       crc=0        finobt=0 spinodes=0
#data     =                       bsize=4096   blocks=144153600, imaxpct=25
#         =                       sunit=0      swidth=0 blks
#naming   =version 2              bsize=4096   ascii-ci=0 ftype=0
#log      =internal               bsize=4096   blocks=31987, version=2
#         =                       sectsz=512   sunit=0 blks, lazy-count=1
#realtime =none                   extsz=4096   blocks=0, rtextents=0
	print("meta-data={:<22s} isize={:<6d} agcount={}, agsize={} blks".format(
		super_block_devname(xfs_mount.m_super), sbp.sb_inodesize, sbp.sb_agcount, sbp.sb_agblocks))

	attr_version = 2 if xfs_sb_version2(sbp, "ATTR2BIT") else 1 if xfs_sb_version(sbp, "ATTRBIT") else 0
	print("         ={:<22s} sectsz={:<5d} attr={}, projid32bit={}".format("",
		sbp.sb_sectsize, attr_version, xfs_sb_version_hasprojid32bit(sbp)))

	print("         ={:<22s} crc={:<8d} finobt={} spinodes={}".format("",
		xfs_sb_version_hascrc(sbp), xfs_sb_version_hasfinobt(sbp), xfs_sb_has_incompat_feat(sbp, "SPINODES")))

	print("         ={:<22s} reflink={}".format("", xfs_sb_version_hasreflink(sbp)))

	print("         ={:<22s} bsize={:<6d} blocks={}, imaxpct={}".format("",
		sbp.sb_blocksize, sbp.sb_dblocks, sbp.sb_imax_pct))

	print("         ={:<22s} sunit={:<6d} swidth={} blks".format("",
		sbp.sb_unit, xfs_mount.m_swidth))

	dirversion = 2 if xfs_sb_version(sbp, "DIRV2BIT") else 1
	try:
		dirblksize = xfs_mount.m_dir_geo.blksize
	except:
		dirblksize = xfs_mount.m_dirblksize
	print("naming   =version {:<14d} bsize={:<6d} ascii-ci={} ftype={}".format(
		dirversion, dirblksize, xfs_sb_version(sbp, "BORGBIT"), xfs_sb_version_hasftype(sbp)))

	logname = xfs_mount.m_logname
	int_ext = "internal" if logname == None or logname == "" else "external"
	logversion = 2 if xfs_version_haslogv2(sbp) else 1
	print("log      ={:<22s} bsize={:<6d} blocks={}, version={}".format(
		int_ext, 1 << sbp.sb_blocklog, sbp.sb_logblocks, logversion))

	print("         ={:<22s} sectsz={:<5d} sunit={} blks, lazy-count={}".format("",
		sbp.sb_logsectsize, sbp.sb_logsunit, xfs_sb_version2(sbp, "LAZYSBCOUNTBIT")))

	rtname = "none" if sbp.sb_rblocks == 0 else "external" if xfs_mount.m_rtname is None else xfs_mount.m_rtname
	print("realtime ={:<22s} extsz={:<6d} blocks={}, rtextents={}".format(rtname,
		sbp.sb_rextsize, sbp.sb_rblocks, sbp.sb_rextents))


# either print overall xfsstats (percpu)
# or per-xfs_mount xfsstats (also percpu)
def show_xfsstats(addr, ilvl=0):
	percpu = get_per_cpu()

	# pattern after nfs stat display
#	for c in percpu.cpu.keys():
#		stats = percpu.per_cpu_struct(c, addr, "

# 
#	percpu = get_per_cpu()
#
#        totals_events = {}
#        total_events_stats = get_enum_tag_value("__NFSIOS_COUNTSMAX", "nfs_stat_eventcounters")
#        totals_bytes = {}
#        total_bytes_stats = get_enum_tag_value("__NFSIOS_BYTESMAX", "nfs_stat_bytecounters")
#        totals_fscache = {}
#        total_fscache_stats = get_enum_tag_value("__NFSIOS_FSCACHEMAX", "nfs_stat_fscachecounters")

#        first_cpu = 1
#        for c in percpu.cpu.keys():
#       for c in xrange(0, percpu.count):
#                io_stats = percpu.per_cpu_struct(c, nfss.io_stats, "nfs_iostats")





def show_xfs_mount(addr, ilvl=0):
	mp = readSU("struct xfs_mount", addr)
	show_xfs_info(addr, ilvl=ilvl+1)

	xfsstats = mp.m_stats.xs_stats
	show_xfsstats(xfsstats, ilvl=ilvl+1)

def show_xfs_sb(addr, ilvl=0):
	print("{}(struct xfs_sb *)0x{:016x}".format(indent_str(ilvl), addr))

	if not check_prune("xfs_sb", addr):

		try:
#			any xfs_sb - specific items to show?
			xfs_sb = readSU("struct xfs_sb", addr)

			print("{}.uuid: ".format(indent_str(ilvl)), end='')
			show_uuid_be(xfs_sb.sb_uuid)
			print("{}.sb_meta_uuid: ".format(indent_str(ilvl)), end='')
			show_uuid_be(xfs_sb.sb_meta_uuid)

			show_xfs_mount(xfs_mount_from_xfs_sb(addr), ilvl=ilvl+1)
		except:
			pass

def show_super_block(addr, ilvl=0):
	print("{}(struct super_block *)0x{:016x}".format(indent_str(ilvl), addr))

	if not check_prune("super_block", addr):
		try:
			sb = readSU("struct super_block", addr)
			print_struct_ptr(sb.s_root, "dentry", ilvl=ilvl, member_name="s_root")

			print("{}{}".format(indent_str(ilvl), get_pathname(sb.s_root, 0)))

#		any super_block - specific items to show?
			show_xfs_mount(xfs_mount_from_sb(addr), ilvl=ilvl+1)
		except:
			pass

def show_xfs_trans(addr, ilvl=0):
#	print_struct_ptr(addr, "xfs_trans", ilvl=ilvl, todo=True)
#	print("{}(struct xfs_trans *)0x{:016x}".format(indent_str(ilvl), addr));

	if not check_prune("xfs_trans", addr):
		try:
			tp = readSU("struct xfs_trans", addr)
			print_struct_ptr(addr, "xfs_trans", ilvl=ilvl, todo=True)

			show_struct_member_simple(tp, "t_log_res", ilvl)
			show_struct_member_simple(tp, "t_log_count", ilvl)
			show_struct_member_simple(tp, "t_blk_res", ilvl)
			show_struct_member_simple(tp, "t_blk_res_used", ilvl)
			show_struct_member_simple(tp, "t_rtx_res", ilvl)
			show_struct_member_simple(tp, "t_rtx_res_used", ilvl)
			show_struct_member_simple_nonzero(tp, "t_icount_delta", ilvl)
			show_struct_member_simple_nonzero(tp, "t_ifree_delta", ilvl)
			show_struct_member_simple_nonzero(tp, "t_fdblocks_delta", ilvl)
			show_struct_member_simple_nonzero(tp, "t_res_fdblocks_delta", ilvl)
			show_struct_member_simple_nonzero(tp, "t_frextents_delta", ilvl)
			show_struct_member_simple_nonzero(tp, "t_res_frextents_delta", ilvl)
			show_struct_member_simple_nonzero(tp, "t_frextents_delta", ilvl)
			show_struct_member_simple_nonzero(tp, "t_res_frextents_delta", ilvl)
			show_struct_member_simple_nonzero(tp, "t_dblocks_delta", ilvl)
			show_struct_member_simple_nonzero(tp, "t_agcount_delta", ilvl)
			show_struct_member_simple_nonzero(tp, "t_imaxpct_delta", ilvl)
			show_struct_member_simple_nonzero(tp, "t_rextsize_delta", ilvl)
			show_struct_member_simple_nonzero(tp, "t_rbmblocks_delta", ilvl)
			show_struct_member_simple_nonzero(tp, "t_rblocks_delta", ilvl)
			show_struct_member_simple_nonzero(tp, "t_rextents_delta", ilvl)
			show_struct_member_simple_nonzero(tp, "t_rextslog_delta", ilvl)

			try:
				l = readListFromHead(tp.t_items, maxel=1000000)
				print("{}entries in t_items: {}".format(indent_str(ilvl), len(l)))
			except:
				pass
			try:
				l = readListFromHead(tp.t_busy, maxel=10000000)
				print("{}entries in t_busy: {}".format(indent_str(ilvl), len(l)))
			except:
				pass
			# t_pflags
			# t_flags

			show_xfs_mount(tp.t_mountp, ilvl=ilvl+1)
		except:
			pass

def show_block_device(addr, ilvl=0):
	if not check_prune("block_device", addr):
		try:
			bdev = readSU("struct block_device", addr)
			print_struct_ptr(bdev, "block_device", ilvl=ilvl, todo=True)
		except:
			pass


def show_xfs_buftarg(addr, ilvl=0):
#	print_struct_ptr(addr, "xfs_buftarg", ilvl=ilvl, todo=True)

	if not check_prune("xfs_buftarg", addr):
		try:
			targ = readSU("struct xfs_buftarg", addr)
			print_struct_ptr(addr, "xfs_buftarg", ilvl=ilvl, todo=True)

			bdev = targ.bt_bdev
			show_block_device(bdev, ilvl=ilvl+1)

		except:
			pass

def show_xfs_buf(addr, ilvl=0):
	print("{}(struct xfs_buf *)0x{:016x}".format(indent_str(ilvl), addr))

	if not check_prune("xfs_buf", addr):

		try:
			xbf = readSU("struct xfs_buf", addr)

			print("{}.b_addr = (struct page *)0x{:016x}".format(indent_str(ilvl), xbf.b_addr))
			print("{}.b_offset = {}".format(indent_str(ilvl), xbf.b_offset))
			print("{}.b_page_count = {}".format(indent_str(ilvl), xbf.b_page_count))
			print("{}.b_pages = (struct page **)0x{:016x}".format(indent_str(ilvl), xbf.b_pages))

			show_xfs_buftarg(xbf.b_target, ilvl=ilvl+1)

#			any xfs_buf - specific items to show?
			show_xfs_trans(xbf.b_transp, ilvl=ilvl+1)
			show_xfs_perag(xbf.b_pag, ilvl=ilvl+1)
			try:
				mount_addr = xfs_mount_from_xfs_buf(xbf)
				if not mount_addr == 0:
					print("calling show_xfs_mount from show_xfs_buf")
					show_xfs_mount(mount_addr, ilvl=ilvl+1)
					print("back")
			except:
				pass
		except:
			pass


def show_xfs_perag(addr, ilvl=0):
	print("{}(struct xfs_perag *)0x{:016x}".format(indent_str(ilvl), addr))

	if not check_prune("xfs_perag", addr):
		try:
			pag = readSU("struct xfs_perag", addr)
			print("{}.pag_agno: {}".format(indent_str(ilvl), pag.pag_agno))
			show_struct_member_simple(pag, "pagi_count", ilvl=ilvl)
			show_struct_member_simple(pag, "pagi_freecount", ilvl=ilvl)
			show_struct_member_simple(pag, "pagf_freecount", ilvl=ilvl)

		except:
			pass

def show_xfs_btblock(addr, ilvl=0):
	btb = readSU("struct xfs_btree_block", addr)

	lsn = ntohll(btb.bb_u.l.bb_lsn)
	bno = ntohll(btb.bb_u.l.bb_blkno)
#	uuid = Addr(btb.bb_u.l.bb_uuid)
#	uuid = readmem(btb.bb_u.l.bb_uuid, 16)

	print("{}(struct xfs_btree_block *)0x{:016x}".format(indent_str(ilvl), btb))
#	print("{}.lsn:block - {}:{}".format(indent_str(ilvl), lsn, bno))
	print("{}.lsn: {}".format(indent_str(ilvl), lsn))

	print("{}.uuid: ".format(indent_str(ilvl)), end='')
	show_uuid_be(btb.bb_u.l)
	print("")


def show_xfs_whatever(addr, struct_type='', ilvl=0):
	if not struct_type == '':
		id = struct_type
	else:
		id = xfs_whatever_id(addr)


	print("0x{:016x} appears to be '{}'".format(addr, id))

	if id == "xfs_mount":
		show_xfs_mount(xfs_mount_from_whatever(id, addr), ilvl=ilvl+1)
		return
	if id == "xfs_sb":
		show_xfs_sb(addr, ilvl=ilvl+1)
		return
	if id == "super_block":
		show_super_block(addr, ilvl=ilvl+1)
		return
	if id == "xfs_buf":
		show_xfs_buf(addr, ilvl=ilvl+1)
		return
	if id == "xfs_inode":
		show_xfs_mount(xfs_mount_from_whatever(id, addr), ilvl=ilvl+1)
		return
	if id == "xfs_trans":
		show_xfs_trans(addr, ilvl=ilvl+1)
		return
	if id == "xlog_ticket":
		show_xlog_ticket(addr, ilvl=ilvl+1)
		return
	if id == "inode":
		show_xfs_mount(xfs_mount_from_inode(addr), ilvl=ilvl+1)
		return
	if id == "xlog":
		show_xfs_mount(xfs_mount_from_xlog(addr), ilvl=ilvl+1)
		show_xlog(addr)
		return
	if id == "xfs_bmap":
		show_xfs_btblock(addr, ilvl=ilvl+1)
		return
	if id == "xfs_cil":
		show_xfs_mount(xfs_mount_from_xfs_cil(addr), ilvl=ilvl+1)
		return
#	print("0x{:016x} appears to be '{}'".format(addr, id))
	print("couldn't print '{}' 0x{:016x}".format(id, addr))


if __name__ == "__main__":
	global prune_list
	prune_list = {}

	import argparse
	opts_parser = argparse.ArgumentParser()
	opts_parser.add_argument('--type', '-t', dest='struct_type', default='', action='store')
	cmd_opts, args = opts_parser.parse_known_args(sys.argv[1:])

	print("type: {}".format(cmd_opts.struct_type))
	print("remaining args: {}".format(*args))


#	if len(sys.argv) > 1:
	if len(args) > 0:
		if args[0] == "convert":
			convert_cmd(args[2:])
		else:
			for arg in args:
				addr = get_arg_value(arg)
				if addr != 0:
					show_xfs_whatever(addr, struct_type=cmd_opts.struct_type)
	else:
		super_blocks = readSymbol("super_blocks")
		sb_list = readSUListFromHead(super_blocks, "s_list", "struct super_block")
		for sb in sb_list:
			if sb.s_type.name == "xfs":
				show_xfs_whatever(sb)
				print("")


# vim: sw=4 ts=4 noexpandtab
