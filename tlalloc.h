/**
 * Copyright (C) 2022 Deadpool
 *
 * Two Layer PM Allocator: allocate blocks and meta blocks/entries
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
 */

#ifndef _HK_TLALLOC_H
#define _HK_TLALLOC_H

#include "hunter.h"

#define TL_BLK      0x1
#define TL_MTA      0x2
#define TL_TYPE_MSK 0x00ff

/* typedef enum {
    PKG_ATTR,
    PKG_CREATE,
    PKG_UNLINK,
    PKG_RENAME,
    PKG_DATA,
    PKG_TYPE_NUM
} HUNT_PKG_TYPE; */

/* PKG_UNLINK can be split into CREATE + UNLINK; we use linker to link these two package */
/* corresponding to package in media */
#define TL_MTA_PKG_ATTR   0x1000 /* fop: truncate operations */
#define TL_MTA_PKG_UNLINK 0x2000 /* fop: unlink operations */
#define TL_MTA_PKG_CREATE 0x4000 /* fop: create/mkdir operations */
#define TL_MTA_PKG_DATA   0x8000 /* I/O: write operations */
#define TL_MTA_TYPE_NUM   4
#define TL_MTA_TYPE_MSK   0xff00

static __always_inline int meta_type_to_idx(u16 type)
{
    switch (type) {
    case TL_MTA_PKG_ATTR: /* fop: truncate operations */
        return 0;
    case TL_MTA_PKG_UNLINK: /* fop: unlink operations */
        return 1;
    case TL_MTA_PKG_CREATE: /* fop: create/mkdir operations */
        return 2;
    case TL_MTA_PKG_DATA: /* I/O: write operations */
        return 3;
    default:
        return -1;
    }
}

#define TL_ALLOC_TYPE(flags)     (flags & TL_TYPE_MSK)
#define TL_ALLOC_MTA_TYPE(flags) (flags & TL_MTA_TYPE_MSK)

typedef struct tl_dnode {
    u64 num;
} tl_dnode_t;

typedef struct tl_mnode {
    /* metadata is allocated in 64B granularity in a 4KiB block */
    u64 bm;
} tl_mnode_t;

typedef struct tl_node {
    union 
    {  
        /* data node */
        struct {
            struct rb_node node;
        };
        
        /* meta node */
        struct {
            struct hlist_node hnode;
            struct list_head list;
        };
    };
    u64 blk;
    union {
        struct tl_dnode dnode;
        struct tl_mnode mnode;
    };
} tl_node_t;

typedef struct data_mgr {
    struct rb_root free_tree;
    spinlock_t spin;
} data_mgr_t;

typedef struct typed_meta_mgr {
    struct list_head free_list;
    DECLARE_HASHTABLE(used_blks, HK_HASH_BITS7);
    u64 entries_perblk;
    u64 entries_mask;
    spinlock_t spin;
} typed_meta_mgr_t;

typedef struct meta_mgr {
    typed_meta_mgr_t tmeta_mgrs[TL_MTA_TYPE_NUM];
} meta_mgr_t;

typedef struct tl_allocator {
    data_mgr_t data_manager;
    meta_mgr_t meta_manager;
    struct hk_range_node rng;
} tl_allocator_t;

typedef struct tlalloc_param {
    u32 req;
    u16 flags;
    struct hk_range_node _ret_rng;
    u32 _ret_allocated;
    tl_node_t *_ret_node;
} tlalloc_param_t;

typedef struct tlfree_param {
    u16 flags;
    u64 blk;
    union {
        struct {
            u64 num;
        };
        struct {
            u32 entrynr;
            u32 entrynum;
        };
    };
    u64 freed;
} tlfree_param_t;

typedef struct tlrestore_param {
    u16 flags;
    u64 blk;
    union {
        struct {
            u64 num;
        };
        struct {
            u32 entrynr;
            u32 entrynum;
        };
    };
    struct list_head affected_nodes;
} tlrestore_param_t;

#endif /* _HK_TLALLOC_H */