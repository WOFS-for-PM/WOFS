#
# Makefile for the HUNTER filesystem routines.
#

HK_PREFETCH_ENABLE := 1
HK_EXTEND_NUM_BLOCKS := 512

obj-m += hunter.o

hunter-y := super.o balloc.o bbuild.o dir.o file.o inode.o ioctl.o \
			namei.o rebuild.o super.o symlink.o sysfs.o \
			linix.o meta.o stats.o mlist.o cmt.o tlalloc.o objm.o generic_cachep.o

EXTRA_CFLAGS += -DHK_PREFETCH_ENABLE=$(HK_PREFETCH_ENABLE)
EXTRA_CFLAGS += -DHK_EXTEND_NUM_BLOCKS=$(HK_EXTEND_NUM_BLOCKS)

all:
	$(MAKE)  -C /lib/modules/$(shell uname -r)/build M=`pwd`

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=`pwd` clean