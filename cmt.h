#ifndef _HK_CMT_H_
#define _HK_CMT_H_

#include "hunter.h"

struct hk_inode_state {
    u64 ino;
    u16 mode;
    u32 uid;
    u32 gid;
    u32 atime;
    u32 mtime;
    u32 ctime;
    u64 size; /* File size after truncation */
};

/* for data block valid/invalid */
enum hk_cmt_data_op {
    CMT_VALID,
    CMT_INVALID
};

enum hk_cmt_data_type {
    DATA,
    ATTR,
    JNL,
    INODE,
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

/* common header */
struct hk_cmt_common_info {
    struct list_head lnode;
    u8 type;
};

struct hk_cmt_data_info {
    struct list_head lnode;
    u8 type;
    u8 op;
    u64 tstamp; /* tstamp when commit */
    u64 addr_start;
    u64 addr_end;
    u64 blk_start;
    u64 blk_end;
};

struct hk_cmt_attr_info {
    struct list_head lnode;
    u8 type;
    u64 tstamp; /* tstamp when commit */
    struct hk_inode_state state;
};

struct hk_cmt_jnl_info {
    struct list_head lnode;
    u8 type;
    // TODO
};

struct hk_cmt_inode_info {
    struct list_head lnode;
    u8 type;
    // TODO
};

/* Decouple from sih for async flush */
struct hk_cmt_node {
    u64 h_addr; /* h_addr in memory, same as hk_inode_data_root */

    struct rb_node rnode; /* List of inodes */
    u64 ino;

#ifdef CONFIG_DECOUPLE_WORKER
    struct hk_cmt_inode_info *cmt_inode; /* The inode entity which backups this inode */
    struct hk_inf_queue data_queue;      /* Data queue for this inode */
    struct hk_inf_queue attr_queue;      /* Attr queue for this inode */
    struct hk_inf_queue jnl_queue;       /* The journal entity which involves this inode */
#else
    struct hk_inf_queue fuse_queue; /* The fused queue contains various metadata */
#endif
};

struct hk_cmt_queue {
    struct rb_root cmt_tree; /* sih list */
    struct mutex lock;
};

#endif
