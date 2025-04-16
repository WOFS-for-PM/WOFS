#ifndef _WOFS_NAMEI_H
#define _WOFS_NAMEI_H

#include "wofs.h"

struct wofs_dentry {
	u8	    name_len;		        /* length of the dentry name */
	u8	    valid;		            /* Invalid now? */
	__le16	links_count;
	__le32	mtime;			        /* For both mtime and ctime */
	__le64	ino;			        /* inode no pointed to by this entry */
    __le64  tstamp;					/* FIXME: tstamp should be used to append */
    //! We don't need this now
	__le32	csum;			        /* entry checksum */
	u8	    name[WOFS_NAME_LEN + 1];	/* File name */
} __attribute((__packed__));

struct wofs_dentry_info {
	struct hlist_node node;
	unsigned long hash;
	struct wofs_dentry *direntry;	
};

#define MAX_DENTRY_PER_BLK (WOFS_PBLK_SZ(sbi) / sizeof(struct wofs_dentry))

#endif /* _WOFS_NAMEI_H */