#ifndef _HK_CMT_H_
#define _HK_CMT_H_

#include "hunter.h"

enum hk_cmt_info_type {
    CMT_VALID_DATA,
    CMT_INVALID_DATA,
    CMT_UPDATE_DATA,
    CMT_DELETE_DATA,
    CMT_NEW_INODE,
    CMT_DELETE_INODE,
    CMT_UNLINK_INODE,
    CMT_CLOSE_INODE,
    MAX_CMT_TYPE
};

/* commit data */
struct hk_cmt_dbatch {
    u64 addr_start;
    u64 addr_end;
    u64 blk_start;
    u64 blk_end;
    u64 dst_blks;
};

/* attr related information (inode check point, icp) */
struct hk_cmt_icp {
    u64 ino;
    u16 mode;
    u32 uid;
    u32 gid;
    u32 atime;
    u32 mtime;
    u32 ctime;
    u64 size; /* File size after truncation */
    u64 tstamp;
    u16 links_count;
    u32 flags;
    u32 generation;
};

static inline void hk_init_cmt_dbatch(struct hk_cmt_dbatch *batch, u64 addr, u64 blk_cur, u64 dst_blks)
{
    batch->addr_start = batch->addr_end = addr;
    batch->blk_start = batch->blk_end = blk_cur;
    batch->dst_blks = dst_blks;
}

static inline void hk_inc_cmt_dbatch(struct hk_cmt_dbatch *batch)
{
    batch->addr_end += HK_PBLK_SZ;
    batch->blk_end += 1;
    batch->dst_blks -= 1;
}

static inline void hk_init_and_inc_cmt_dbatch(struct hk_cmt_dbatch *batch, u64 addr, u64 blk_cur, u64 dst_blks)
{
    BUG_ON(dst_blks != 1);
    hk_init_cmt_dbatch(batch, addr, blk_cur, dst_blks);
    hk_inc_cmt_dbatch(batch);
}

static inline void hk_next_cmt_dbatch(struct hk_cmt_dbatch *batch)
{
    batch->addr_start = batch->addr_end;
    batch->blk_start = batch->blk_end;
    if (batch->dst_blks == 0) {
        batch->dst_blks = -1;
    }
}

static inline bool hk_is_cmt_dbatch_valid(struct hk_cmt_dbatch *batch)
{
    return (batch->dst_blks >= 0);
}

/* general header */
struct hk_cmt_info {
    struct list_head lnode;
    u8 type;
};

struct hk_cmt_data_info {
    struct list_head lnode;
    u8 type;
    u64 tstamp; /* tstamp when commit */
    u64 addr_start;
    u64 addr_end;
    u64 blk_start;
    u64 size;
    u32 cmtime;
    u8 paddings[3];
} __attribute__((packed));

static_assert(sizeof(struct hk_cmt_data_info) == 64, "hk_cmt_data_info size is not 64");

// TODO: Specific ICP for new inode, unlink inode
struct hk_cmt_new_inode_info {
    struct list_head lnode;
    u8 type;
    struct hk_cmt_icp inode_cp;
    struct hk_cmt_icp dir_inode_cp;
    struct hk_dentry *direntry;
};

struct hk_cmt_unlink_inode_info {
    struct list_head lnode;
    u8 type;
    struct hk_cmt_icp inode_cp;
    struct hk_cmt_icp dir_inode_cp;
    struct hk_dentry *direntry;
    bool invalidate;
};

struct hk_cmt_delete_inode_info {
    struct list_head lnode;
    u8 type;
};

struct hk_cmt_close_info {
    struct list_head lnode;
    u8 type;
};

/* Decouple from sih for async flush */
struct hk_cmt_node {
    u64 h_addr; /* h_addr in memory, same as hk_inode_data_root */

    struct rb_node rnode; /* rb_node */
    u64 ino;
    /* Note that it will be hard to edit red black tree when worker is processing
      (i.e., by iterating the rb tree. So, we just lazily edit the node's state to invalid) */
    bool valid; /* if this node is valid. */
    struct mutex processing; /* if this node is being processed by worker */

    struct hk_inf_queue op_q; /* Data queue for this inode */
};

struct hk_cmt_queue {
    struct rb_root *cmt_forest;
    struct mutex *locks;
};

#endif
