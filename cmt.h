#ifndef _WOFS_CMT_H_
#define _WOFS_CMT_H_

#include "wofs.h"

struct wofs_inode_state {
    u64 ino;
    u16 mode;
    u32 uid;
    u32 gid;
    u32 atime;
    u32 mtime;
    u32 ctime;
    u64 size; /* File size after truncation */
};

enum wofs_cmt_type {
    CMT_VALID,
    CMT_INVALID
};

struct wofs_cmt_batch {
    u64 addr_start;
    u64 addr_end;
    u64 blk_start;
    u64 dst_blks;
};

static inline void wofs_init_cmt_batch(struct super_block *sb, struct wofs_cmt_batch *batch, u64 addr, u64 blk_cur, u64 dst_blks)
{
    batch->addr_start = batch->addr_end = addr;
    batch->blk_start = blk_cur;
    batch->dst_blks = dst_blks;
}

static inline void wofs_inc_cmt_batch(struct super_block *sb, struct wofs_cmt_batch *batch)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    batch->addr_end += WOFS_PBLK_SZ(sbi);
    batch->dst_blks -= 1;
}

static inline void wofs_next_cmt_batch(struct super_block *sb, struct wofs_cmt_batch *batch)
{
    batch->addr_start = batch->addr_end;
    if (batch->dst_blks == 0) {
        batch->dst_blks = -1;
    }
}

static inline bool wofs_is_cmt_batch_valid(struct super_block *sb, struct wofs_cmt_batch *batch)
{
    return (batch->dst_blks >= 0);
}

struct wofs_cmt_info {
    struct ch_slot slot;
    u8 type;
    u16 mode;
    u32 blk_start;
    u32 uid;
    u32 gid;
    u32 time; /* for atime, ctime, and mtime */
    u64 size; /* File size after truncation */
    u64 ino;
    u64 addr_start;
    u64 addr_end;
    u64 tstamp; /* tstamp when commit */
    u8 paddings[16];
};

// int a = sizeof(struct wofs_cmt_info);

struct wofs_cmt_queue {
    DEFINE_CHASHTABLE(table, WOFS_CMT_QUEUE_BITS);
    spinlock_t locks[1 << WOFS_CMT_QUEUE_BITS];
    u64 nitems[1 << WOFS_CMT_QUEUE_BITS];
    void *fetchers;
    int nfetchers
};

#endif
