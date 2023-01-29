/**
 * Copyright (C) 2022 Deadpool
 *
 * Object management: Manage PKG and OBJ.
 *
 * This file is part of hunter-userspace.
 *
 * hunter-userspace is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * hunter-userspace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with hunter-userspace.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Implementation of the package management system:
 * 1. Package metadata transactions
 *
 * typedef enum
 * {
 *   PKG_CREATE,  |Inode(64B)|AttrChange(64B)|AttrChangeParent(64B)|Dentry(128B)|PKG(64B)| (6 MetaEntry)
 *   PKG_UNLINK,  |AttrChangeParent(64B)|PKG(64B with unlink_spec)| (2 MetaEntry)
 *   PKG_RENAME,  |PKG_CREATE|->|PKG_UNLINK|
 *   PKG_TYPE_NUM
 * } HUNT_PKG_TYPE;
 *
 * 2. Allocation
 *
 * As continuos as possible, we do not want to any type of random small access.
 *
 * 3. Eviction
 *
 * This part is managed by upper layer (File Management)
 *
 * 4. Handle of Fragmentation
 *
 * Using a reorganization method. Trigger manually or in the background.
 *
 */

#ifndef _OBJ_H
#define _OBJ_H

#include "hunter.h"

/* ==== in-media structures ==== */
struct pm_space_bm_hdr {
    u16 type;
    u32 blks;
} __attribute__((__packed__));

typedef enum {
    PKG_DATA,
    PKG_CREATE,
    PKG_UNLINK,
    PKG_RENAME, /* Rename can be split into create + unlink */
    PKG_ATTR,
    PKG_TYPE_NUM
} HUNT_PKG_TYPE;

struct rename_spec_hdr {
    u64 next;  /* next package's offset. From CREATE to UNLINK */
    u32 valid; /* valid flag, one of the pair should hold this */
} __attribute__((__packed__));

static_assert(sizeof(struct rename_spec_hdr) <= 56);

struct unlink_spec_hdr {
    u32 unlinked_ino;
} __attribute__((__packed__));

static_assert(sizeof(struct unlink_spec_hdr) <= 56);

typedef enum {
    OBJ_DATA,
    OBJ_INODE,
    OBJ_ATTR,
    OBJ_DENTRY,
    OBJ_PKGHDR,
    OBJ_TYPE_NUM
} HK_OBJ_TYPE;

struct hk_obj_hdr {
    u32 magic;
    u32 type;
    u64 vtail;
    u32 crc32; /* fence-once */
    u8 reserved[8];
} __attribute__((__packed__));

struct hk_pkg_hdr {
    struct hk_obj_hdr hdr;
    u16 pkg_type;
    union {
        struct unlink_spec_hdr unlink_hdr;
        struct rename_spec_hdr rename_hdr;
        u8 reserved[34];
    };
} __attribute__((__packed__));

static_assert(sizeof(struct hk_pkg_hdr) == 64);

struct hk_obj_inode {
    struct hk_obj_hdr hdr;
    /* static part of inode */
    u32 ino;           /* inode number */
    u32 i_flags;       /* Inode flags */
    u64 i_xattr;       /* Extended attribute block */
    u32 i_generation;  /* File version (for NFS) */
    u64 i_create_time; /* Create time */

    u8 reserved[8];
} __attribute__((__packed__));

static_assert(sizeof(struct hk_obj_inode) == 64);

struct hk_obj_attr {
    struct hk_obj_hdr hdr;
    /* dynamic part of inode */
    u32 ino;           /* inode number */
    u16 i_mode;        /* File mode */
    u32 i_uid;         /* Owner Uid */
    u32 i_gid;         /* Group Id */
    u32 i_ctime;       /* Inode modification time */
    u32 i_mtime;       /* Inode Modification time */
    u32 i_atime;       /* Access time */
    u64 i_size;        /* File size after truncation */
    u16 i_links_count; /* Links count if i_links_count == 0, it is a removed entry */
} __attribute__((__packed__));

static_assert(sizeof(struct hk_obj_attr) == 64);

struct hk_obj_dentry {
    struct hk_obj_hdr hdr;
    u32 ino;
    u32 parent_ino;
    u8 name[HK_NAME_LEN];
} __attribute__((__packed__));

static_assert(sizeof(struct hk_obj_dentry) == 128);

struct hk_obj_data {
    struct hk_obj_hdr hdr;
    u32 ino;
    u64 ofs; /* offset in file */
    u32 blk;
    u64 num;
    u32 i_cmtime; /* for both mtime and ctime */
    u64 i_size;
} __attribute__((__packed__));

static_assert(sizeof(struct hk_obj_data) == 64);

#define OBJ_DATA_SIZE   sizeof(struct hk_obj_data)
#define OBJ_INODE_SIZE  sizeof(struct hk_obj_inode)
#define OBJ_ATTR_SIZE   sizeof(struct hk_obj_attr)
#define OBJ_DENTRY_SIZE sizeof(struct hk_obj_dentry)
#define OBJ_PKGHDR_SIZE sizeof(struct hk_pkg_hdr)

/* ==== in-DRAM structures ==== */

typedef struct obj_ref_hdr {
    u64 addr; /* in-pm addr, offset */
    u32 ref;  /* reference count of obj */
    u32 ino;  /* which file this obj belongs to */
} obj_ref_hdr_t;

/* I/O related reference */
#define DATA_HOLE          0
#define DATA_REF           1
#define DATA_IS_HOLE(type) ((type) == DATA_HOLE)
#define DATA_IS_REF(type)  ((type) == DATA_REF)

typedef struct obj_ref_data {
    obj_ref_hdr_t hdr; /* in-pm entry hdr */
    struct list_head node;
    u64 next;        /* next in-pm addr, might be used for cacheable design */
    u64 prev;        /* prev in-pm addr, might be used for cacheable design */
    u64 data_offset; /* in-pm data offset */
    u64 ofs;         /* In-File offset */
    u64 num;         /* Number of blocks */
    u8 type;
} obj_ref_data_t;

typedef struct obj_ref_dentry {
    obj_ref_hdr_t hdr;
    struct list_head node;
    u32 target_ino;
    unsigned long hash;
} obj_ref_dentry_t;

/* File operations related reference */
typedef struct obj_ref_inode { /* __INODE_MANAGE_THIS */
    obj_ref_hdr_t hdr;
} obj_ref_inode_t;

typedef struct obj_ref_attr { /* __INODE_MANAGE_THIS */
    obj_ref_hdr_t hdr;
    u16 from_pkg;
    u32 dep_addr;
} obj_ref_attr_t;

typedef struct d_obj_ref_list {
    struct hlist_node hnode;
    u32 ino;
    struct list_head list;
} d_obj_ref_list_t;

/* use d_root to fast locate objs in the media */
typedef struct d_root {
    DECLARE_HASHTABLE(data_obj_refs, HK_HASH_BITS7);   /* key is ino, value is the list of data of this ino */
    DECLARE_HASHTABLE(dentry_obj_refs, HK_HASH_BITS7); /* key is parent ino, value is the list of dentries of this ino */
    spinlock_t data_lock;
    spinlock_t dentry_lock;
} d_root_t;

/* imap: key ino, value hk_inode_info_header */
typedef struct imap {
    DECLARE_HASHTABLE(map, HK_HASH_BITS7);
} imap_t;

/* for pending table */
typedef struct claim_req {
    struct hlist_node hnode;
    u64 req_pkg_addr;
    u64 dep_pkg_addr;
    u16 req_pkg_type;
    u16 dep_pkg_type;
} claim_req_t;

/* build this in the mount time */
typedef struct obj_mgr {
    struct hk_sb_info *sbi;                          /* the superblock */
    d_root_t *d_roots;                               /* the root of all objs, the number equals to the number of split layouts */
    int num_d_roots;                                 /* the number of d_roots */
    imap_t prealloc_imap;                            /* used to fast locate per file objs, key is ino, value is hk_inode */
    DECLARE_HASHTABLE(pending_table, HK_HASH_BITS7); /* used to handle dependency issues. e.g., to reclaim UNLINK space, we must pend the request into list until corresponding CREATE is claimed.   */
} obj_mgr_t;

typedef struct attr_update {
    u64 addr;          /* In-PM attr offset */
    u16 from_pkg;      /* From which pkg */
    u64 dep_addr;      /* If from_pkg is UNLINK, then dep_addr points the CREATE pkg */
    u16 i_mode;        /* File mode */
    u32 i_uid;         /* Owner Uid */
    u32 i_gid;         /* Group Id */
    u32 i_ctime;       /* Inode modification time */
    u32 i_mtime;       /* Inode Modification time */
    u32 i_atime;       /* Access time */
    u64 i_size;        /* File size after truncation */
    u16 i_links_count; /* Links count if i_links_count == 0, it is a removed entry */
} attr_update_t;

typedef struct data_update {
    bool build_from_exist;
    void *exist_ref;
    u64 addr;     /* In-PM data pkg offset */
    u32 blk;      /* In-PM blk */
    u32 ofs;      /* In-File offset */
    u32 num;      /* Number of blocks */
    u32 i_cmtime; /* for both mtime and ctime */
    u64 i_size;
} data_update_t;

typedef struct inode_update {
    u64 addr; /* In-PM inode offset */
    union {
        unsigned long ino;
        struct hk_inode_info_header *sih;
    };
} inode_update_t;

typedef struct in_pkg_param {
    /* does this package belong to an larger package */
    bool partial;
    /* if the package belongs to an larger package, then pass these arguments */
    u16 wrapper_pkg_type;
    u32 next;
    void *private;
} in_pkg_param_t;

typedef struct in_create_pkg_param {
    bool create_pm_only;    /* for rename */
} in_create_pkg_param_t;

/* out param region */
typedef struct out_pkg_param {
    u64 addr;
    void *private;
} out_pkg_param_t;

typedef struct out_create_pkg_param {
    obj_ref_dentry_t *ref;
} out_create_pkg_param_t;

#define MTA_PKG_DATA_BLK   (OBJ_DATA_SIZE >> HUNTER_MTA_SHIFT)
#define MTA_PKG_ATTR_BLK   (OBJ_ATTR_SIZE >> HUNTER_MTA_SHIFT)
#define MTA_PKG_CREATE_BLK ((OBJ_INODE_SIZE + 2 * OBJ_ATTR_SIZE + OBJ_DENTRY_SIZE + OBJ_PKGHDR_SIZE) >> HUNTER_MTA_SHIFT)
#define MTA_PKG_UNLINK_BLK ((OBJ_ATTR_SIZE + OBJ_PKGHDR_SIZE) >> HUNTER_MTA_SHIFT)

#define MTA_PKG_DATA_SIZE   (MTA_PKG_DATA_BLK << HUNTER_MTA_SHIFT)
#define MTA_PKG_ATTR_SIZE   (MTA_PKG_ATTR_BLK << HUNTER_MTA_SHIFT)
#define MTA_PKG_CREATE_SIZE (MTA_PKG_CREATE_BLK << HUNTER_MTA_SHIFT)
#define MTA_PKG_UNLINK_SIZE (MTA_PKG_UNLINK_BLK << HUNTER_MTA_SHIFT)

#define GET_OFS_INBLK(ofs_addr) ((ofs_addr) & (HUNTER_BLK_SIZE - 1))
#define GET_ENTRYNR(ofs_addr) \
    (GET_OFS_INBLK(ofs_addr) >> HUNTER_MTA_SHIFT)

static inline int get_pkg_hdr(u64 pkg_start, u16 pkg_type, u64 *pkg_hdr)
{
    *pkg_hdr = 0;
    switch (pkg_type) {
    case PKG_ATTR:
        *pkg_hdr = pkg_start;
        break;
    case PKG_DATA:
        *pkg_hdr = pkg_start;
        break;
    case PKG_RENAME:
        break;
    case PKG_CREATE:
        *pkg_hdr = pkg_start + OBJ_INODE_SIZE + 2 * OBJ_ATTR_SIZE + OBJ_DENTRY_SIZE;
        break;
    case PKG_UNLINK:
        *pkg_hdr = pkg_start + OBJ_ATTR_SIZE;
        break;
    default:
        break;
    }
    return 0;
}

#endif