#
# Makefile for the HUNTER filesystem routines.
#

MAX_OBJ_REF_DATA := 0

obj-m += hunter.o

hunter-y := super.o balloc.o bbuild.o dir.o file.o inode.o ioctl.o \
			namei.o rebuild.o super.o symlink.o sysfs.o \
			linix.o meta.o stats.o mlist.o cmt.o tlalloc.o objm.o generic_cachep.o copy_user_64_ext.o usercopy_64_ext.o

EXTRA_CFLAGS += -DMAX_OBJ_REF_DATA=$(MAX_OBJ_REF_DATA) \

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=`pwd`

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=`pwd` clean