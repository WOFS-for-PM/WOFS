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
#include "hunter.h"

#define UINT8_SHIFT 3
#define UINT8_MASK  0x07

#define UINT32_BITS 32
#define UINT64_BITS 64

/* max supply for consecutive 8 bits */
static const u64 bm64_consecutive_masks[8][64] = {
    /* 1 */
    {
        0x0000000000000001, 0x0000000000000002, 0x0000000000000004, 0x0000000000000008,
        0x0000000000000010, 0x0000000000000020, 0x0000000000000040, 0x0000000000000080,
        0x0000000000000100, 0x0000000000000200, 0x0000000000000400, 0x0000000000000800,
        0x0000000000001000, 0x0000000000002000, 0x0000000000004000, 0x0000000000008000,
        0x0000000000010000, 0x0000000000020000, 0x0000000000040000, 0x0000000000080000,
        0x0000000000100000, 0x0000000000200000, 0x0000000000400000, 0x0000000000800000,
        0x0000000001000000, 0x0000000002000000, 0x0000000004000000, 0x0000000008000000,
        0x0000000010000000, 0x0000000020000000, 0x0000000040000000, 0x0000000080000000,
        0x0000000100000000, 0x0000000200000000, 0x0000000400000000, 0x0000000800000000,
        0x0000001000000000, 0x0000002000000000, 0x0000004000000000, 0x0000008000000000,
        0x0000010000000000, 0x0000020000000000, 0x0000040000000000, 0x0000080000000000,
        0x0000100000000000, 0x0000200000000000, 0x0000400000000000, 0x0000800000000000,
        0x0001000000000000, 0x0002000000000000, 0x0004000000000000, 0x0008000000000000,
        0x0010000000000000, 0x0020000000000000, 0x0040000000000000, 0x0080000000000000,
        0x0100000000000000, 0x0200000000000000, 0x0400000000000000, 0x0800000000000000,
        0x1000000000000000, 0x2000000000000000, 0x4000000000000000, 0x8000000000000000},
    /* 2 */
    {
        0x0000000000000003, 0x0000000000000006, 0x000000000000000c, 0x0000000000000018,
        0x0000000000000030, 0x0000000000000060, 0x00000000000000c0, 0x0000000000000180,
        0x0000000000000300, 0x0000000000000600, 0x0000000000000c00, 0x0000000000001800,
        0x0000000000003000, 0x0000000000006000, 0x000000000000c000, 0x0000000000018000,
        0x0000000000030000, 0x0000000000060000, 0x00000000000c0000, 0x0000000000180000,
        0x0000000000300000, 0x0000000000600000, 0x0000000000c00000, 0x0000000001800000,
        0x0000000003000000, 0x0000000006000000, 0x000000000c000000, 0x0000000018000000,
        0x0000000030000000, 0x0000000060000000, 0x00000000c0000000, 0x0000000180000000,
        0x0000000300000000, 0x0000000600000000, 0x0000000c00000000, 0x0000001800000000,
        0x0000003000000000, 0x0000006000000000, 0x000000c000000000, 0x0000018000000000,
        0x0000030000000000, 0x0000060000000000, 0x00000c0000000000, 0x0000180000000000,
        0x0000300000000000, 0x0000600000000000, 0x0000c00000000000, 0x0001800000000000,
        0x0003000000000000, 0x0006000000000000, 0x000c000000000000, 0x0018000000000000,
        0x0030000000000000, 0x0060000000000000, 0x00c0000000000000, 0x0180000000000000,
        0x0300000000000000, 0x0600000000000000, 0x0c00000000000000, 0x1800000000000000,
        0x3000000000000000, 0x6000000000000000, 0xc000000000000000, 0xFFFFFFFFFFFFFFFF},
    /* 3 */
    {
        0x0000000000000007, 0x000000000000000e, 0x000000000000001c, 0x0000000000000038,
        0x0000000000000070, 0x00000000000000e0, 0x00000000000001c0, 0x0000000000000380,
        0x0000000000000700, 0x0000000000000e00, 0x0000000000001c00, 0x0000000000003800,
        0x0000000000007000, 0x000000000000e000, 0x000000000001c000, 0x0000000000038000,
        0x0000000000070000, 0x00000000000e0000, 0x00000000001c0000, 0x0000000000380000,
        0x0000000000700000, 0x0000000000e00000, 0x0000000001c00000, 0x0000000003800000,
        0x0000000007000000, 0x000000000e000000, 0x000000001c000000, 0x0000000038000000,
        0x0000000070000000, 0x00000000e0000000, 0x00000001c0000000, 0x0000000380000000,
        0x0000000700000000, 0x0000000e00000000, 0x0000001c00000000, 0x0000003800000000,
        0x0000007000000000, 0x000000e000000000, 0x000001c000000000, 0x0000038000000000,
        0x0000070000000000, 0x00000e0000000000, 0x00001c0000000000, 0x0000380000000000,
        0x0000700000000000, 0x0000e00000000000, 0x0001c00000000000, 0x0003800000000000,
        0x0007000000000000, 0x000e000000000000, 0x001c000000000000, 0x0038000000000000,
        0x0070000000000000, 0x00e0000000000000, 0x01c0000000000000, 0x0380000000000000,
        0x0700000000000000, 0x0e00000000000000, 0x1c00000000000000, 0x3800000000000000,
        0x7000000000000000, 0xe000000000000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
    /* 4 */
    {
        0x000000000000000f, 0x000000000000001e, 0x000000000000003c, 0x0000000000000078,
        0x00000000000000f0, 0x00000000000001e0, 0x00000000000003c0, 0x0000000000000780,
        0x0000000000000f00, 0x0000000000001e00, 0x0000000000003c00, 0x0000000000007800,
        0x000000000000f000, 0x000000000001e000, 0x000000000003c000, 0x0000000000078000,
        0x00000000000f0000, 0x00000000001e0000, 0x00000000003c0000, 0x0000000000780000,
        0x0000000000f00000, 0x0000000001e00000, 0x0000000003c00000, 0x0000000007800000,
        0x000000000f000000, 0x000000001e000000, 0x000000003c000000, 0x0000000078000000,
        0x00000000f0000000, 0x00000001e0000000, 0x00000003c0000000, 0x0000000780000000,
        0x0000000f00000000, 0x0000001e00000000, 0x0000003c00000000, 0x0000007800000000,
        0x000000f000000000, 0x000001e000000000, 0x000003c000000000, 0x0000078000000000,
        0x00000f0000000000, 0x00001e0000000000, 0x00003c0000000000, 0x0000780000000000,
        0x0000f00000000000, 0x0001e00000000000, 0x0003c00000000000, 0x0007800000000000,
        0x000f000000000000, 0x001e000000000000, 0x003c000000000000, 0x0078000000000000,
        0x00f0000000000000, 0x01e0000000000000, 0x03c0000000000000, 0x0780000000000000,
        0x0f00000000000000, 0x1e00000000000000, 0x3c00000000000000, 0x7800000000000000,
        0xf000000000000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
    /* 5 */
    {
        0x000000000000001f, 0x000000000000003e, 0x000000000000007c, 0x00000000000000f8,
        0x00000000000001f0, 0x00000000000003e0, 0x00000000000007c0, 0x0000000000000f80,
        0x0000000000001f00, 0x0000000000003e00, 0x0000000000007c00, 0x000000000000f800,
        0x000000000001f000, 0x000000000003e000, 0x000000000007c000, 0x00000000000f8000,
        0x00000000001f0000, 0x00000000003e0000, 0x00000000007c0000, 0x0000000000f80000,
        0x0000000001f00000, 0x0000000003e00000, 0x0000000007c00000, 0x000000000f800000,
        0x000000001f000000, 0x000000003e000000, 0x000000007c000000, 0x00000000f8000000,
        0x00000001f0000000, 0x00000003e0000000, 0x00000007c0000000, 0x0000000f80000000,
        0x0000001f00000000, 0x0000003e00000000, 0x0000007c00000000, 0x000000f800000000,
        0x000001f000000000, 0x000003e000000000, 0x000007c000000000, 0x00000f8000000000,
        0x00001f0000000000, 0x00003e0000000000, 0x00007c0000000000, 0x0000f80000000000,
        0x0001f00000000000, 0x0003e00000000000, 0x0007c00000000000, 0x000f800000000000,
        0x001f000000000000, 0x003e000000000000, 0x007c000000000000, 0x00f8000000000000,
        0x01f0000000000000, 0x03e0000000000000, 0x07c0000000000000, 0x0f80000000000000,
        0x1f00000000000000, 0x3e00000000000000, 0x7c00000000000000, 0xf800000000000000,
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
    /* 6 */
    {
        0x000000000000003f, 0x000000000000007e, 0x00000000000000fc, 0x00000000000001f8,
        0x00000000000003f0, 0x00000000000007e0, 0x0000000000000fc0, 0x0000000000001f80,
        0x0000000000003f00, 0x0000000000007e00, 0x000000000000fc00, 0x000000000001f800,
        0x000000000003f000, 0x000000000007e000, 0x00000000000fc000, 0x00000000001f8000,
        0x00000000003f0000, 0x00000000007e0000, 0x0000000000fc0000, 0x0000000001f80000,
        0x0000000003f00000, 0x0000000007e00000, 0x000000000fc00000, 0x000000001f800000,
        0x000000003f000000, 0x000000007e000000, 0x00000000fc000000, 0x00000001f8000000,
        0x00000003f0000000, 0x00000007e0000000, 0x0000000fc0000000, 0x0000001f80000000,
        0x0000003f00000000, 0x0000007e00000000, 0x000000fc00000000, 0x000001f800000000,
        0x000003f000000000, 0x000007e000000000, 0x00000fc000000000, 0x00001f8000000000,
        0x00003f0000000000, 0x00007e0000000000, 0x0000fc0000000000, 0x0001f80000000000,
        0x0003f00000000000, 0x0007e00000000000, 0x000fc00000000000, 0x001f800000000000,
        0x003f000000000000, 0x007e000000000000, 0x00fc000000000000, 0x01f8000000000000,
        0x03f0000000000000, 0x07e0000000000000, 0x0fc0000000000000, 0x1f80000000000000,
        0x3f00000000000000, 0x7e00000000000000, 0xfc00000000000000, 0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
    /* 7 */
    {
        0x000000000000007f, 0x00000000000000fe, 0x00000000000001fc, 0x00000000000003f8,
        0x00000000000007f0, 0x0000000000000fe0, 0x0000000000001fc0, 0x0000000000003f80,
        0x0000000000007f00, 0x000000000000fe00, 0x000000000001fc00, 0x000000000003f800,
        0x000000000007f000, 0x00000000000fe000, 0x00000000001fc000, 0x00000000003f8000,
        0x00000000007f0000, 0x0000000000fe0000, 0x0000000001fc0000, 0x0000000003f80000,
        0x0000000007f00000, 0x000000000fe00000, 0x000000001fc00000, 0x000000003f800000,
        0x000000007f000000, 0x00000000fe000000, 0x00000001fc000000, 0x00000003f8000000,
        0x00000007f0000000, 0x0000000fe0000000, 0x0000001fc0000000, 0x0000003f80000000,
        0x0000007f00000000, 0x000000fe00000000, 0x000001fc00000000, 0x000003f800000000,
        0x000007f000000000, 0x00000fe000000000, 0x00001fc000000000, 0x00003f8000000000,
        0x00007f0000000000, 0x0000fe0000000000, 0x0001fc0000000000, 0x0003f80000000000,
        0x0007f00000000000, 0x000fe00000000000, 0x001fc00000000000, 0x003f800000000000,
        0x007f000000000000, 0x00fe000000000000, 0x01fc000000000000, 0x03f8000000000000,
        0x07f0000000000000, 0x0fe0000000000000, 0x1fc0000000000000, 0x3f80000000000000,
        0x7f00000000000000, 0xfe00000000000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
    /* 8 */
    {
        0x00000000000000ff, 0x00000000000001fe, 0x00000000000003fc, 0x00000000000007f8,
        0x0000000000000ff0, 0x0000000000001fe0, 0x0000000000003fc0, 0x0000000000007f80,
        0x000000000000ff00, 0x000000000001fe00, 0x000000000003fc00, 0x000000000007f800,
        0x00000000000ff000, 0x00000000001fe000, 0x00000000003fc000, 0x00000000007f8000,
        0x0000000000ff0000, 0x0000000001fe0000, 0x0000000003fc0000, 0x0000000007f80000,
        0x000000000ff00000, 0x000000001fe00000, 0x000000003fc00000, 0x000000007f800000,
        0x00000000ff000000, 0x00000001fe000000, 0x00000003fc000000, 0x00000007f8000000,
        0x0000000ff0000000, 0x0000001fe0000000, 0x0000003fc0000000, 0x0000007f80000000,
        0x000000ff00000000, 0x000001fe00000000, 0x000003fc00000000, 0x000007f800000000,
        0x00000ff000000000, 0x00001fe000000000, 0x00003fc000000000, 0x00007f8000000000,
        0x0000ff0000000000, 0x0001fe0000000000, 0x0003fc0000000000, 0x0007f80000000000,
        0x000ff00000000000, 0x001fe00000000000, 0x003fc00000000000, 0x007f800000000000,
        0x00ff000000000000, 0x01fe000000000000, 0x03fc000000000000, 0x07f8000000000000,
        0x0ff0000000000000, 0x1fe0000000000000, 0x3fc0000000000000, 0x7f80000000000000,
        0xff00000000000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}};

u32 bm64_fast_search_consecutive_bits(u64 bm, u32 bits)
{
    const u64 *mask = bm64_consecutive_masks[bits - 1];
    u32 i = 0;
    u64 res1, res2, res3, res4;
    INIT_TIMING(time);

    bm = ~bm;
    HK_START_TIMING(bm_search_t, time);
    for (i = 0; i < UINT64_BITS; i += 4) {
        res1 = (bm & mask[i]) ^ mask[i];
        res2 = (bm & mask[i + 1]) ^ mask[i + 1];
        res3 = (bm & mask[i + 2]) ^ mask[i + 2];
        res4 = (bm & mask[i + 3]) ^ mask[i + 3];

        if (!res1) {
            HK_END_TIMING(bm_search_t, time);
            return i;
        } else if (!res2) {
            HK_END_TIMING(bm_search_t, time);
            return i + 1;
        } else if (!res3) {
            HK_END_TIMING(bm_search_t, time);
            return i + 2;
        } else if (!res4) {
            HK_END_TIMING(bm_search_t, time);
            return i + 3;
        }
    }

    HK_END_TIMING(bm_search_t, time);
    return UINT64_BITS;
}

void bm_set(u8 *bm, u32 i)
{
    bm[i >> UINT8_SHIFT] |= (1 << (i & UINT8_MASK));
}

void bm_clear(u8 *bm, u32 i)
{
    bm[i >> UINT8_SHIFT] &= ~(1 << (i & UINT8_MASK));
}

u8 bm_test(u8 *bm, u32 i)
{
    return bm[i >> UINT8_SHIFT] & (1 << (i & UINT8_MASK));
}

tl_node_t *tl_create_node(void)
{
    tl_node_t *node = hk_alloc_tl_node();
    node->blk = 0;
    node->node.rb_left = NULL;
    node->node.rb_right = NULL;
    return node;
}

__always_inline void tl_build_alloc_param(tlalloc_param_t *param, u64 req, u16 flags)
{
    param->flags = flags;
    param->req = req;
    param->_ret_node = NULL;
    param->_ret_allocated = 0;
}

/* num is entrynr(32)|entrynum(32)  */
__always_inline void tl_build_free_param(tlfree_param_t *param, u64 blk, u64 num, u16 flags)
{
    param->flags = flags;
    if (TL_ALLOC_TYPE(flags) == TL_BLK) {
        param->blk = blk;
        param->num = num;
    } else if (TL_ALLOC_TYPE(flags) == TL_MTA) {
        param->blk = blk;
        param->entrynr = (num >> 32) & 0xFFFFFFFF;
        param->entrynum = num & 0xFFFFFFFF;
    }
}

/* similar to free_param_t */
__always_inline void tl_build_restore_param(tlrestore_param_t *param, u64 blk, u64 num, u16 flags)
{
    param->flags = flags;
    if (TL_ALLOC_TYPE(flags) == TL_BLK) {
        param->blk = blk;
        param->num = num;
    } else if (TL_ALLOC_TYPE(flags) == TL_MTA) {
        param->blk = blk;
        param->entrynr = (num >> 32) & 0xFFFFFFFF;
        param->entrynum = num & 0xFFFFFFFF;
    }
    INIT_LIST_HEAD(&param->affected_nodes);
}

void tl_free_node(tl_node_t *node)
{
    if (node) {
        hk_free_tl_node(node);
    }
}

static inline int tl_node_compare(void *a, void *b)
{
    const u64 key_a = (const u64)a;
    const u64 key_b = (const u64)b;
    return key_a - key_b;
}

static int tl_tree_insert_node(struct rb_root_cached *tree, tl_node_t *new_node)
{
    tl_node_t *curr;
    struct rb_node **temp, *parent;
    int compVal;
    bool left_most = true;

    temp = &(tree->rb_root.rb_node);
    parent = NULL;

    while (*temp) {
        curr = container_of(*temp, tl_node_t, node);
        compVal = tl_node_compare(curr->blk, new_node->blk);
        parent = *temp;

        if (compVal > 0) {
            temp = &((*temp)->rb_left);
        } else if (compVal < 0) {
            temp = &((*temp)->rb_right);
            left_most = false;
        } else {
            hk_dbg("%s: node %lu - %lu already exists: "
                   "%lu - %lu\n",
                   __func__, new_node->blk, new_node->dnode.num + new_node->blk - 1,
                   curr->blk, curr->blk + curr->dnode.num - 1);
            return -EINVAL;
        }
    }

    rb_link_node(&new_node->node, parent, temp);
    rb_insert_color_cached(&new_node->node, tree, left_most);

    return 0;
}

/* return 1 if found, 0 if not found. Ret node indicates the node that is exact smaller than the blk */
static int tl_tree_find_node(struct rb_root_cached *tree, u64 blk, tl_node_t **ret_node)
{
    tl_node_t *curr = NULL;
    struct rb_node *temp;
    int compVal;
    int ret = 0;

    temp = tree->rb_root.rb_node;

    while (temp) {
        curr = container_of(temp, tl_node_t, node);
        compVal = tl_node_compare(curr->blk, blk);

        if (compVal > 0) {
            temp = temp->rb_left;
        } else if (compVal < 0) {
            temp = temp->rb_right;
        } else {
            ret = 1;
            break;
        }
    }

    *ret_node = curr;

    return ret;
}

/* flags indicate whether find data blocks or meta-block */
static int tl_tree_find_free_slot(struct rb_root_cached *tree, u64 blk, u64 num, u16 flags, tl_node_t **prev, tl_node_t **next)
{
    tl_node_t *ret_node = NULL;
    struct rb_node *tmp;
    int ret;
    u64 rng_low = blk;
    u64 rng_high = blk + num - 1;
    u64 ret_node_rng_low;
    u64 ret_node_rng_high;

    if (TL_ALLOC_TYPE(flags) == TL_MTA) {
        BUG_ON(num != 1);
    }

    ret = tl_tree_find_node(tree, blk, &ret_node);
    if (ret) {
        hk_dbg("%s ERROR: %lu - %lu already in free list\n",
               __func__, blk, blk + num - 1);
        return -EINVAL;
    }

    ret_node_rng_low = ret_node->blk;
    ret_node_rng_high = TL_ALLOC_TYPE(flags) == TL_BLK ? ret_node->blk + ret_node->dnode.num - 1 : ret_node->blk;

    if (!ret_node) {
        *prev = *next = NULL;
    } else if (ret_node_rng_high < rng_low) {
        *prev = ret_node;
        tmp = rb_next(&ret_node->node);
        if (tmp) {
            *next = container_of(tmp, tl_node_t, node);
        } else {
            *next = NULL;
        }
    } else if (ret_node_rng_low > rng_high) {
        *next = ret_node;
        tmp = rb_prev(&ret_node->node);
        if (tmp) {
            *prev = container_of(tmp, tl_node_t, node);
        } else {
            *prev = NULL;
        }
    } else {
        hk_dbg("%s ERROR: %lu - %lu overlaps with existing "
               "node %lu - %lu\n",
               __func__, rng_low, rng_high, ret_node_rng_low,
               ret_node_rng_high);
        return -EINVAL;
    }

    return 0;
}

void tl_mgr_init(tl_allocator_t *alloc, u64 blk_size, u64 meta_size)
{
    data_mgr_t *data_mgr = &alloc->data_manager;
    typed_meta_mgr_t *tmeta_mgr;
    tl_node_t *node;
    u64 blk = alloc->rng.high - alloc->rng.low + 1, i;

    data_mgr->free_tree = RB_ROOT_CACHED;
    spin_lock_init(&data_mgr->spin);
    node = tl_create_node();
    node->blk = alloc->rng.low;
    node->dnode.num = blk;
    tl_tree_insert_node(&data_mgr->free_tree, node);

    hk_dbgv("%s: free tree: %lu - %lu for cpu %d\n", __func__, node->blk, node->blk + blk - 1, alloc->cpuid);

    /* typed metadata managers */
    for (i = 0; i < TL_MTA_TYPE_NUM; i++) {
        tmeta_mgr = &alloc->meta_manager.tmeta_mgrs[i];
        hash_init(tmeta_mgr->used_blks);
        INIT_LIST_HEAD(&tmeta_mgr->free_list);
        tmeta_mgr->entries_perblk = blk_size / meta_size;
        BUG_ON(tmeta_mgr->entries_perblk > UINT64_BITS);
        if (tmeta_mgr->entries_perblk == UINT64_BITS) {
            tmeta_mgr->entries_mask = (u64)-1;
        } else {
            tmeta_mgr->entries_mask = (1 << tmeta_mgr->entries_perblk) - 1;
        }
        spin_lock_init(&tmeta_mgr->spin);
    }
}

int tl_alloc_init(tl_allocator_t *alloc, int cpuid, u64 blk, u64 num, u32 blk_size, u32 meta_size)
{
    alloc->rng.low = blk;
    alloc->rng.high = blk + num - 1;
    alloc->cpuid = cpuid;
    tl_mgr_init(alloc, blk_size, meta_size);
    return 0;
}

static bool __tl_try_find_avail_data_blks(void *key, void *value, void *data)
{
    tlalloc_param_t *param = data;
    tl_node_t *node = value;
    u64 allocated = 0;

    allocated = node->dnode.num >= param->req ? param->req : node->dnode.num;
    node->blk = node->blk + allocated;
    node->dnode.num -= allocated;

    param->_ret_node = node;
    param->_ret_rng.low = node->blk - allocated;
    param->_ret_rng.high = node->blk - 1;
    param->_ret_allocated = allocated;

    return true;
}

#define tl_traverse_tree(tree, temp, node) \
    for (temp = rb_first_cached(tree), node = rb_entry(temp, tl_node_t, node); temp; temp = rb_next(temp), node = rb_entry(temp, tl_node_t, node))

/* alloc as many as possible */
s32 tlalloc(tl_allocator_t *alloc, tlalloc_param_t *param)
{
    data_mgr_t *data_mgr = &alloc->data_manager;
    meta_mgr_t *meta_mgr = &alloc->meta_manager;
    struct list_head *pos;
    tl_node_t *node;
    struct rb_node *temp;
    u16 flags = param->flags;
    s32 entrynr = -1;
    s32 ret = 0;
    u8 i;
    INIT_TIMING(time);

    if (TL_ALLOC_TYPE(flags) == TL_BLK) {
        spin_lock(&data_mgr->spin);
        tl_traverse_tree(&data_mgr->free_tree, temp, node)
        {
            if (__tl_try_find_avail_data_blks((void *)node->blk, node, param)) {
                break;
            }
        }
        if (param->_ret_node) {
            if (param->_ret_node->dnode.num == 0) {
                rb_erase_cached(&param->_ret_node->node, &data_mgr->free_tree);
                tl_free_node(param->_ret_node);
            }
            spin_unlock(&data_mgr->spin);
        } else {
            ret = -ENOSPC;
            spin_unlock(&data_mgr->spin);
            goto out;
        }
    } else if (TL_ALLOC_TYPE(flags) == TL_MTA) {
        HK_START_TIMING(tl_alloc_meta_t, time);
        typed_meta_mgr_t *tmeta_mgr;
        u8 idx = meta_type_to_idx(TL_ALLOC_MTA_TYPE(flags));
        tmeta_mgr = &meta_mgr->tmeta_mgrs[idx];
        spin_lock(&tmeta_mgr->spin);
    retry:
        list_for_each(pos, &tmeta_mgr->free_list)
        {
            node = list_entry(pos, tl_node_t, list);
            entrynr = bm64_fast_search_consecutive_bits(node->mnode.bm, param->req);
            if (entrynr != UINT64_BITS) {
                param->_ret_node = node;
                param->_ret_rng.low = node->blk;
                param->_ret_rng.high = entrynr;
                param->_ret_allocated = param->req;
                for (i = 0; i < param->req; i++) {
                    bm_set((u8 *)&node->mnode.bm, entrynr + i);
                }
                /* too full to allocate */
                if ((node->mnode.bm & tmeta_mgr->entries_mask) == tmeta_mgr->entries_mask) {
                    list_del(&node->list);
                }
                spin_unlock(&tmeta_mgr->spin);
                HK_END_TIMING(tl_alloc_meta_t, time);
                return 0;
            }
        }
        spin_unlock(&tmeta_mgr->spin);

        /* alloc a block to hold metadata */
        tlalloc_param_t alloc_blk_param;

        tl_build_alloc_param(&alloc_blk_param, 1, TL_BLK);
        ret = tlalloc(alloc, &alloc_blk_param);
        if (ret < 0) {
            goto out;
        }
        node = tl_create_node();
        node->blk = alloc_blk_param._ret_rng.low;
        node->mnode.bm = 0;

        spin_lock(&tmeta_mgr->spin);
        hash_add(tmeta_mgr->used_blks, &node->hnode, node->blk);

        hk_dbgv("alloc blk %lu for meta type %x (%s)\n", node->blk, TL_ALLOC_MTA_TYPE(flags), meta_type_to_str(TL_ALLOC_MTA_TYPE(flags)));

        /* head insert */
        list_add_tail(&node->list, &tmeta_mgr->free_list);
        goto retry;
    }

out:
    return ret;
}

static bool __tl_try_insert_data_blks(struct rb_root_cached *tree, tl_node_t *prev, tl_node_t *next, tlfree_param_t *param)
{
    u64 rng_low = param->blk;
    u64 rng_high = param->blk + param->num - 1;
    u64 prev_rng_low = prev ? prev->blk : 0;
    u64 prev_rng_high = prev ? prev->blk + prev->dnode.num - 1 : 0;
    u64 next_rng_low = next ? next->blk : 0;
    u64 next_rng_high = next ? next->blk + next->dnode.num - 1 : 0;

    if (prev && next && (rng_low == prev_rng_high + 1) &&
        (rng_high + 1 == next_rng_low)) {
        /* fits the hole */
        rb_erase_cached(&next->node, tree);
        prev->dnode.num += (param->num + next->dnode.num);
        tl_free_node(next);
        param->freed = param->num;
        return true;
    } else if (prev && (rng_low == prev_rng_high + 1)) {
        /* Aligns left */
        prev->dnode.num += param->num;
        param->freed = param->num;
        return true;
    } else if (next && (rng_high + 1 == next_rng_low)) {
        /* Aligns right */
        next->blk = param->blk;
        next->dnode.num += param->num;
        param->freed = param->num;
        return true;
    }

    return false;
}

static bool __list_check_entry_freed(struct list_head *entry)
{
    return entry->next == LIST_POISON1 && entry->prev == LIST_POISON2;
}

void tlfree(tl_allocator_t *alloc, tlfree_param_t *param)
{
    data_mgr_t *data_mgr = &alloc->data_manager;
    meta_mgr_t *meta_mgr = &alloc->meta_manager;
    tl_node_t *node;
    struct rb_node *temp;
    u16 flags = param->flags;

    param->freed = 0;

    if (TL_ALLOC_TYPE(flags) == TL_BLK) {
        u64 blk = param->blk;
        u64 num = param->num;
        tl_node_t *prev = NULL;
        tl_node_t *next = NULL;
        int ret;

        hk_dbgv("free blk %lu, num %lu\n", blk, num);
        if (alloc->rng.low > blk || alloc->rng.high < blk + num - 1) {
            hk_dbg("try free blk %lu, num %lu at %d\n", blk, num, alloc->cpuid);
            BUG_ON(1);
        }

        spin_lock(&data_mgr->spin);
        ret = tl_tree_find_free_slot(&data_mgr->free_tree, blk, num, flags, &prev, &next);
        if (ret) {
            hk_dbg("fail to find free data slot for [%lu, %lu] at layout %d\n", blk, blk + num - 1, alloc->cpuid);
            BUG_ON(1);
        }
        __tl_try_insert_data_blks(&data_mgr->free_tree, prev, next, param);
        spin_unlock(&data_mgr->spin);

        if (param->freed == 0) {
            node = tl_create_node();
            node->blk = blk;
            node->dnode.num = num;
            spin_lock(&data_mgr->spin);
            tl_tree_insert_node(&data_mgr->free_tree, node);
            spin_unlock(&data_mgr->spin);
        }
    } else if (TL_ALLOC_TYPE(flags) == TL_MTA) {
        u64 blk = param->blk;
        u32 entrynr = param->entrynr;
        u32 entrynum = param->entrynum;
        s32 i = 0;
        typed_meta_mgr_t *tmeta_mgr;
        tl_node_t *cur;
        int idx = meta_type_to_idx(TL_ALLOC_MTA_TYPE(flags));

        hk_dbgv("free meta blk %lu, entrynr %u, entrynum %u, type %x (%s) at %d layout.\n", blk, entrynr, entrynum, TL_ALLOC_MTA_TYPE(flags), meta_type_to_str(TL_ALLOC_MTA_TYPE(flags)), alloc->cpuid);

        tmeta_mgr = &meta_mgr->tmeta_mgrs[idx];

        spin_lock(&tmeta_mgr->spin);
        hash_for_each_possible(tmeta_mgr->used_blks, cur, hnode, blk)
        {
            if (cur->blk == blk) {
                for (i = 0; i < entrynum; i++) {
                    bm_clear((u8 *)&cur->mnode.bm, entrynr + i);
                }
                param->freed += entrynum;
                /* rls block */
                if (cur->mnode.bm == 0) {
                    hash_del(&cur->hnode);
                    /* The corner case is that one node is held by only used_blks table, */
                    /* since it is too full to do further allocation, see `tlalloc()`. */
                    /* Thus, we shall not del node from list again. */
                    if (__list_check_entry_freed(&cur->list) == false) {
                        list_del(&cur->list);
                    }
                    tl_free_node(cur);

                    tlfree_param_t free_blk_param;
                    tl_build_free_param(&free_blk_param, blk, 1, TL_BLK);
                    tlfree(alloc, &free_blk_param);
                }
                break;
            }
        }

        if (param->freed == 0) {
            BUG_ON(1);
        }

        spin_unlock(&tmeta_mgr->spin);
    }
}

struct affect_node {
    struct list_head list;
    tl_node_t *node;
};

static bool __tl_try_restore_data_blks(void *key, void *value, void *data)
{
    tlrestore_param_t *param = data;
    tl_node_t *node = value;
    u64 blk = node->blk;
    u64 num = node->dnode.num;
    struct affect_node *anode;

    if (!(blk + num < param->blk || param->blk + param->num < blk)) {
        anode = kmalloc(sizeof(struct affect_node), GFP_ATOMIC);
        anode->node = node;
        list_add_tail(&anode->list, &param->affected_nodes);
    }

    if (param->blk > blk + num) {
        return true;
    }

    return false;
}

void tlrestore(tl_allocator_t *alloc, tlrestore_param_t *param)
{
    data_mgr_t *data_mgr = &alloc->data_manager;
    meta_mgr_t *meta_mgr = &alloc->meta_manager;
    tl_node_t *node;
    struct list_head *pos, *n;
    struct rb_node *temp;
    tlrestore_param_t data_restore_param;
    u16 flags = param->flags;

    if (TL_ALLOC_TYPE(flags) == TL_BLK) {
        u64 blk = param->blk;
        u64 num = param->num;
        struct affect_node *anode;

        spin_lock(&data_mgr->spin);
        tl_traverse_tree(&data_mgr->free_tree, temp, node)
        {
            if (__tl_try_restore_data_blks((void *)node->blk, node, param)) {
                break;
            }
        }
        spin_unlock(&data_mgr->spin);

        /* traverse affected_nodes */
        list_for_each_safe(pos, n, &param->affected_nodes)
        {
            anode = list_entry(pos, struct affect_node, list);
            node = anode->node;
            if (blk <= node->blk && blk + num >= node->blk + node->dnode.num) {
                rb_erase_cached(&node->node, &data_mgr->free_tree);
                tl_free_node(node);
            } else if (blk <= node->blk && blk + num < node->blk + node->dnode.num) {
                node->dnode.num = node->blk + node->dnode.num - blk - num;
                node->blk = blk + num;
            } else if (blk > node->blk && blk + num >= node->blk + node->dnode.num) {
                node->dnode.num = blk - node->blk;
            } else if (blk > node->blk && blk + num < node->blk + node->dnode.num) {
                tl_node_t *new_node = tl_create_node();
                new_node->blk = blk + num;
                new_node->dnode.num = node->blk + node->dnode.num - new_node->blk;
                spin_lock(&data_mgr->spin);
                tl_tree_insert_node(&data_mgr->free_tree, new_node);
                spin_unlock(&data_mgr->spin);
                node->dnode.num = blk - node->blk;
            }
            list_del(&anode->list);
            kfree(anode);
        }
        BUG_ON(!list_empty((const struct list_head *)&param->affected_nodes));
    } else if (TL_ALLOC_TYPE(flags) == TL_MTA) {
        u64 blk = param->blk;
        u32 entrynr = param->entrynr;
        u32 entrynum = param->entrynum;
        s32 i = 0;
        typed_meta_mgr_t *tmeta_mgr;
        tl_node_t *cur;

        hk_dbgv("restore meta blk %lu, entrynr %u, entrynum %u, type %x (%s) at %d layout.\n", blk, entrynr, entrynum, TL_ALLOC_MTA_TYPE(flags), meta_type_to_str(TL_ALLOC_MTA_TYPE(flags)), alloc->cpuid);

        tmeta_mgr = &meta_mgr->tmeta_mgrs[meta_type_to_idx(TL_ALLOC_MTA_TYPE(flags))];
        spin_lock(&tmeta_mgr->spin);
        node = NULL;
        hash_for_each_possible(tmeta_mgr->used_blks, cur, hnode, blk)
        {
            if (cur->blk == blk) {
                node = cur;
                break;
            }
        }

        if (!node) {
            tl_build_restore_param(&data_restore_param, blk, 1, TL_BLK);
            tlrestore(alloc, &data_restore_param);

            /* create new meta node */
            node = tl_create_node();
            node->blk = blk;
            node->mnode.bm = 0;
            hash_add(tmeta_mgr->used_blks, &node->hnode, blk);
            list_add_tail(&node->list, &tmeta_mgr->free_list);
        }

        for (i = 0; i < entrynum; i++) {
            bm_set((u8 *)&node->mnode.bm, entrynr + i);
        }
        /* too full to alloc */
        if ((node->mnode.bm & tmeta_mgr->entries_mask) == tmeta_mgr->entries_mask) {
            list_del(&node->list);
        }
        spin_unlock(&tmeta_mgr->spin);
    }
}

void tl_destory(tl_allocator_t *alloc)
{
    data_mgr_t *data_mgr = &alloc->data_manager;
    meta_mgr_t *meta_mgr = &alloc->meta_manager;
    tl_node_t *cur;
    struct rb_node *temp;
    struct list_head *pos, *n;
    struct hlist_node *htemp;
    int bkt, i;

    /* destroy data node */
    temp = rb_first_cached(&data_mgr->free_tree);
    while (temp) {
        cur = container_of(temp, tl_node_t, node);
        temp = rb_next(temp);
        rb_erase_cached(&cur->node, &data_mgr->free_tree);
        tl_free_node(cur);
    }

    /* destroy meta node */
    for (i = 0; i < TL_MTA_TYPE_NUM; i++) {
        typed_meta_mgr_t *tmeta_mgr;
        tmeta_mgr = &meta_mgr->tmeta_mgrs[i];

        list_for_each_safe(pos, n, &tmeta_mgr->free_list)
        {
            cur = list_entry(pos, tl_node_t, list);
            list_del(&cur->list);
        }

        hash_for_each_safe(tmeta_mgr->used_blks, bkt, htemp, cur, hnode)
        {
            hash_del(&cur->hnode);
            tl_free_node(cur);
        }
    }
}

static bool __tl_dump_dnode(void *key, void *value, void *data)
{
    tl_node_t *node = value;
    hk_info("[dnode]: start at %lu, end at %lu, len %lu\n", node->blk, node->blk + node->dnode.num - 1, node->dnode.num);
    return false;
}

static bool __tl_dump_mnode(void *key, void *value, void *data)
{
    tl_node_t *node = value;
    hk_info("[mnode]: block %lu, alloc bitmap: 0x%lx\n", node->blk, node->mnode.bm);
    return false;
}

void tl_dump_data_mgr(data_mgr_t *data_mgr)
{
    struct rb_node *temp;
    tl_node_t *node;

    spin_lock(&data_mgr->spin);
    tl_traverse_tree(&data_mgr->free_tree, temp, node)
    {
        __tl_dump_dnode((void *)node->blk, node, NULL);
    }
    spin_unlock(&data_mgr->spin);
}

void tl_dump_meta_mgr(meta_mgr_t *meta_mgr)
{
    typed_meta_mgr_t *tmeta_mgr;
    struct list_head *pos;
    tl_node_t *node;
    int i;

    for (i = 0; i < TL_MTA_TYPE_NUM; i++) {
        tmeta_mgr = &meta_mgr->tmeta_mgrs[i];
        spin_lock(&tmeta_mgr->spin);
        list_for_each(pos, &tmeta_mgr->free_list)
        {
            node = list_entry(pos, tl_node_t, list);
            __tl_dump_mnode((void *)node->blk, node, NULL);
        }
        spin_unlock(&tmeta_mgr->spin);
    }
}