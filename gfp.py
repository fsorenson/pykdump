#!/usr/bin/python

def get_arg_value(arg):
	try:
		if '.' in arg: return float(arg)
		if arg.lower().startswith('0x'): return int(arg, 16)
		if arg.startswith('0') and all(c in string.octdigits for c in arg): return int(arg, 8)
#               if all(c in string.intdigits for c in arg): ### stupid python doesn't have string.intdigits?
		if all(c in '0123456789' for c in arg): return int(arg, 10)
		return int(arg, 16)
	except ValueError:
		return 0

GFP_C_PROG = '''
#include <stdio.h>

#define __STR(a) #a
#define _STR(a) __STR(a)
#define STR(a) _STR(a)

#define _PASTE(a,b)           a##b
#define _PASTE3(a,b,c)        a##b##c
#define PASTE(a,b)            _PASTE(a,b)
#define PASTE3(a,b,c)         _PASTE3(a,b,c)

#define print_gfp(g) do { \
	printf("%s - 0x%x\n", STR(__GFP_) STR(g), PASTE(__GFP_, g)); \
} while (0)

#define print_gfp_alias(g) do { \
	printf("%s - 0x%x\n", STR(GFP_) STR(g), PASTE(GFP_, g)); \
} while (0)

#define ___GFP_DMA              0x01u
#define ___GFP_HIGHMEM          0x02u
#define ___GFP_DMA32            0x04u
#define ___GFP_MOVABLE          0x08u
#define ___GFP_WAIT             0x10u
#define ___GFP_HIGH             0x20u
#define ___GFP_IO               0x40u
#define ___GFP_FS               0x80u
#define ___GFP_COLD             0x100u
#define ___GFP_NOWARN           0x200u
#define ___GFP_REPEAT           0x400u
#define ___GFP_NOFAIL           0x800u
#define ___GFP_NORETRY          0x1000u
#define ___GFP_MEMALLOC         0x2000u
#define ___GFP_COMP             0x4000u
#define ___GFP_ZERO             0x8000u
#define ___GFP_NOMEMALLOC       0x10000u
#define ___GFP_HARDWALL         0x20000u
#define ___GFP_THISNODE         0x40000u
#define ___GFP_RECLAIMABLE      0x80000u
#define ___GFP_ACCOUNT          0x100000u
#define ___GFP_NOTRACK          0x200000u
#define ___GFP_NO_KSWAPD        0x400000u
#define ___GFP_OTHER_NODE       0x800000u
#define ___GFP_WRITE            0x1000000u

void show_gfps() {

#define __GFP_DMA       (___GFP_DMA)
#define __GFP_HIGHMEM   (___GFP_HIGHMEM)
#define __GFP_DMA32     (___GFP_DMA32)
#define __GFP_MOVABLE   (___GFP_MOVABLE)  /* Page is movable */
#define GFP_ZONEMASK    (__GFP_DMA|__GFP_HIGHMEM|__GFP_DMA32|__GFP_MOVABLE)

print_gfp(DMA);
print_gfp(HIGHMEM);
print_gfp(DMA32);
print_gfp(MOVABLE);

#define __GFP_WAIT      (___GFP_WAIT)    /* Can wait and reschedule? */
#define __GFP_HIGH      (___GFP_HIGH)    /* Should access emergency pools? */
#define __GFP_IO        (___GFP_IO)      /* Can start physical IO? */
#define __GFP_FS        (___GFP_FS)      /* Can call down to low-level FS? */
#define __GFP_COLD      (___GFP_COLD)    /* Cache-cold page required */
#define __GFP_NOWARN    (___GFP_NOWARN)  /* Suppress page allocation failure warning */
#define __GFP_REPEAT    (___GFP_REPEAT)  /* See above */
#define __GFP_NOFAIL    (___GFP_NOFAIL)  /* See above */
#define __GFP_NORETRY   (___GFP_NORETRY) /* See above */
#define __GFP_MEMALLOC  (___GFP_MEMALLOC)/* Allow access to emergency reserves */
#define __GFP_COMP      (___GFP_COMP)    /* Add compound page metadata */
#define __GFP_ZERO      (___GFP_ZERO)    /* Return zeroed page on success */
#define __GFP_NOMEMALLOC (___GFP_NOMEMALLOC) /* Don't use emergency reserves.
                                                         * This takes precedence over the
                                                         * __GFP_MEMALLOC flag if both are
                                                         * set
                                                         */
print_gfp(WAIT);
print_gfp(HIGH);
print_gfp(IO);
print_gfp(FS);
print_gfp(COLD);
print_gfp(NOWARN);
print_gfp(REPEAT);
print_gfp(NOFAIL);
print_gfp(NORETRY);
print_gfp(MEMALLOC);
print_gfp(COMP);
print_gfp(ZERO);
print_gfp(NOMEMALLOC);

#define __GFP_HARDWALL   (___GFP_HARDWALL) /* Enforce hardwall cpuset memory allocs */
#define __GFP_THISNODE  (___GFP_THISNODE)/* No fallback, no policies */
#define __GFP_ACCOUNT   (___GFP_ACCOUNT)
#define __GFP_RECLAIMABLE (___GFP_RECLAIMABLE) /* Page is reclaimable */
#define __GFP_NOTRACK   (___GFP_NOTRACK)  /* Don't track with kmemcheck */

#define __GFP_NO_KSWAPD (___GFP_NO_KSWAPD)
#define __GFP_OTHER_NODE (___GFP_OTHER_NODE) /* On behalf of other node */
#define __GFP_WRITE     (___GFP_WRITE)   /* Allocator intends to dirty page */

#define __GFP_NOTRACK_FALSE_POSITIVE (__GFP_NOTRACK)

#define __GFP_BITS_SHIFT 25     /* Room for N __GFP_FOO bits */
#define __GFP_BITS_MASK (((1 << __GFP_BITS_SHIFT) - 1))
print_gfp(HARDWALL);
print_gfp(THISNODE);
print_gfp(ACCOUNT);
print_gfp(RECLAIMABLE);
print_gfp(NOTRACK);
print_gfp(NO_KSWAPD);
print_gfp(OTHER_NODE);
print_gfp(WRITE);
//print_gfp(NOTRACK_FALSE_POSITIVE);
}

#define GFP_NOWAIT      (GFP_ATOMIC & ~__GFP_HIGH)
#define GFP_ATOMIC      (__GFP_HIGH)
#define GFP_NOIO        (__GFP_WAIT)
#define GFP_NOFS        (__GFP_WAIT | __GFP_IO)
#define GFP_KERNEL      (__GFP_WAIT | __GFP_IO | __GFP_FS)
#define GFP_KERNEL_ACCOUNT (GFP_KERNEL | __GFP_ACCOUNT)
#define GFP_TEMPORARY   (__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_RECLAIMABLE)
#define GFP_USER        (__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL)
#define GFP_HIGHUSER    (__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL | __GFP_HIGHMEM)
#define GFP_HIGHUSER_MOVABLE    (__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL | __GFP_HIGHMEM | __GFP_MOVABLE)
#define GFP_IOFS        (__GFP_IO | __GFP_FS)
#define GFP_TRANSHUGE   (GFP_HIGHUSER_MOVABLE | __GFP_COMP | __GFP_NOMEMALLOC | __GFP_NORETRY | __GFP_NOWARN | __GFP_NO_KSWAPD)

#define GFP_THISNODE    (__GFP_THISNODE | __GFP_NOWARN | __GFP_NORETRY)
/* This mask makes up all the page movable related flags */
#define GFP_MOVABLE_MASK (__GFP_RECLAIMABLE|__GFP_MOVABLE)

/* Control page allocator reclaim behavior */
#define GFP_RECLAIM_MASK (__GFP_WAIT|__GFP_HIGH|__GFP_IO|__GFP_FS|__GFP_NOWARN|__GFP_REPEAT|__GFP_NOFAIL|__GFP_NORETRY|__GFP_MEMALLOC|__GFP_NOMEMALLOC)

/* Control slab gfp mask during early boot */
#define GFP_BOOT_MASK (__GFP_BITS_MASK & ~(__GFP_WAIT|__GFP_IO|__GFP_FS))

/* Control allocation constraints */
#define GFP_CONSTRAINT_MASK (__GFP_HARDWALL|__GFP_THISNODE)

/* Do not use these with a slab allocator */
#define GFP_SLAB_BUG_MASK (__GFP_DMA32|__GFP_HIGHMEM|~__GFP_BITS_MASK)

/* Flag - indicates that the buffer will be suitable for DMA.  Ignored on some
   platforms, used as appropriate on others */

#define GFP_DMA         __GFP_DMA

/* 4GB DMA on some platforms */
#define GFP_DMA32       __GFP_DMA32

// gfp aliases
void show_gfp_aliases() {

// zero?
// #define GFP_NOWAIT      (GFP_ATOMIC & ~__GFP_HIGH)
//#define GFP_NOWAIT      (__GFP_HIGH ~__GFP_HIGH)
print_gfp_alias(NOWAIT);

//#define GFP_KERNEL_ACCOUNT (GFP_KERNEL | __GFP_ACCOUNT)
print_gfp_alias(KERNEL_ACCOUNT);

//#define GFP_TRANSHUGE	(GFP_HIGHUSER_MOVABLE | __GFP_COMP | __GFP_NOMEMALLOC | __GFP_NORETRY | __GFP_NOWARN | __GFP_NO_KSWAPD)
//#define GFP_TRANSHUGE	(__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL | __GFP_HIGHMEM | __GFP_MOVABLE | __GFP_COMP | __GFP_NOMEMALLOC | __GFP_NORETRY | __GFP_NOWARN | __GFP_NO_KSWAPD)
print_gfp_alias(TRANSHUGE);

//#define GFP_HIGHUSER_MOVABLE    (__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL | __GFP_HIGHMEM | __GFP_MOVABLE)
print_gfp_alias(HIGHUSER_MOVABLE);

// skip the masks
// #define GFP_MOVABLE_MASK (__GFP_RECLAIMABLE|__GFP_MOVABLE)
// #define GFP_RECLAIM_MASK (__GFP_WAIT|__GFP_HIGH|__GFP_IO|__GFP_FS|__GFP_NOWARN|__GFP_REPEAT|__GFP_NOFAIL|__GFP_NORETRY|__GFP_MEMALLOC|__GFP_NOMEMALLOC)
// #define GFP_BOOT_MASK (__GFP_BITS_MASK & ~(__GFP_WAIT|__GFP_IO|__GFP_FS))
// #define GFP_CONSTRAINT_MASK (__GFP_HARDWALL|__GFP_THISNODE)
// #define GFP_SLAB_BUG_MASK (__GFP_DMA32|__GFP_HIGHMEM|~__GFP_BITS_MASK)

//#define GFP_HIGHUSER    (__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL | __GFP_HIGHMEM)
//#define GFP_USER        (__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL)
print_gfp_alias(HIGHUSER);
print_gfp_alias(USER);

//#define GFP_TEMPORARY   (__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_RECLAIMABLE)
//#define GFP_KERNEL      (__GFP_WAIT | __GFP_IO | __GFP_FS)
//#define GFP_NOFS        (__GFP_WAIT | __GFP_IO)
//#define GFP_IOFS        (__GFP_IO | __GFP_FS)
//#define GFP_THISNODE    (__GFP_THISNODE | __GFP_NOWARN | __GFP_NORETRY)
print_gfp_alias(TEMPORARY);
print_gfp_alias(KERNEL);
print_gfp_alias(NOFS);
print_gfp_alias(IOFS);
print_gfp_alias(THISNODE);

//#define GFP_NOIO        (__GFP_WAIT)
print_gfp_alias(NOIO);

//#define GFP_ATOMIC      (__GFP_HIGH)
print_gfp_alias(ATOMIC);

//#define GFP_DMA         __GFP_DMA
//#define GFP_DMA32       __GFP_DMA32
print_gfp_alias(DMA);
print_gfp_alias(DMA32);

}

int main(int argc, char *argv[]) {
	printf("raw gfps\n");
	show_gfps();
	printf("\n");
	printf("aliases\n");
	show_gfp_aliases();
//	print_gfp_alias(ATOMIC);
//print_gfp_alias(NOWAIT);
//print_gfp_alias(
}
// gfp.c

$ gcc gfp.c -o gfp
$ ./gfp
raw gfps
__GFP_DMA - 0x1
__GFP_HIGHMEM - 0x2
__GFP_DMA32 - 0x4
...

$ ./gfp | awk 'substr($1,1,2)=="__" { printf "#define %s  %s\n", substr($1,7), $NF}'
'''

GFP_FLAGS_C = '''
#define DMA  0x1
#define HIGHMEM  0x2
#define DMA32  0x4
#define MOVABLE  0x8
#define WAIT  0x10
#define HIGH  0x20
#define IO  0x40
#define FS  0x80
#define COLD  0x100
#define NOWARN  0x200
#define REPEAT  0x400
#define NOFAIL  0x800
#define NORETRY  0x1000
#define MEMALLOC  0x2000
#define COMP  0x4000
#define ZERO  0x8000
#define NOMEMALLOC  0x10000
#define HARDWALL  0x20000
#define THISNODE  0x40000
#define ACCOUNT  0x100000
#define RECLAIMABLE  0x80000
#define NOTRACK  0x200000
#define NO_KSWAPD  0x400000
#define OTHER_NODE  0x800000
#define WRITE  0x1000000
'''

GFP_FLAGS = CDefine(GFP_FLAGS_C)

def flags_to_string(flags, strings):
	result = []
	for name, val in strings.items():
		if flags & val != 0:
			result.append(name)
			flags = flags & ~val
	if flags:
		result.append("0x{:x}".format(flags))
	return "|".join(result)

def show_gfp(gfp):
	s = flags_to_string(gfp, GFP_FLAGS)
	print("0X{:X} - {}".format(gfp, s))


if __name__ == "__main__":
	if len(sys.argv) > 1:
		for arg in sys.argv[1:]:
			gfp = get_arg_value(arg)
			show_gfp(gfp)
	else:
		print("usage: {} <gfp_value> [<gfp_value> ...]".format(sys.argv[0]))


# vim: sw=4 ts=4 noexpandtab
