/*
 * HUNTER File Operation impl.
 *
 * Copyright 2022-2023 Regents of the University of Harbin Institute of Technology, Shenzhen
 * Computer science and technology, Yanqi Pan <deadpoolmine@qq.com>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "hunter.h"

static ssize_t do_dax_mapping_read(struct file *filp, char __user *buf,
                                   size_t len, loff_t *ppos)
{
    struct inode *inode = filp->f_mapping->host;
    struct super_block *sb = inode->i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;

    pgoff_t index, end_index;
    unsigned long offset;
    loff_t isize, pos;
    size_t copied = 0;
    size_t error = 0;
    size_t ra_win = sbi->ra_win;
    int num_readers;

    INIT_TIMING(memcpy_time);

    pos = *ppos;
    index = pos >> PAGE_SHIFT; /* Start from which blk */
    offset = pos & ~PAGE_MASK; /* Start from ofs to the blk */

    if (!access_ok(buf, len)) {
        error = -EFAULT;
        goto out;
    }

    isize = i_size_read(inode); /* Get file size */
    if (!isize)
        goto out;

    hk_dbgv("%s: inode %lu, offset %lld, count %lu, size %lld\n",
            __func__, inode->i_ino, pos, len, isize);

    if (len > isize - pos)
        len = isize - pos;

    if (len <= 0)
        goto out;

    end_index = (isize - 1) >> PAGE_SHIFT;

    do {
        unsigned long nr, left, i, j, iter, remain;
        unsigned long blk_addr;
        void *dax_mem = NULL;
        bool zero = false;
        size_t win;

        /* nr is the maximum number of bytes to copy from this page */
        if (index >= end_index) {
            if (index > end_index)
                goto out;
            nr = ((isize - 1) & ~PAGE_MASK) + 1;
            if (nr <= offset)
                goto out;
        }

        if (ENABLE_META_PACK(sb)) {
            obj_ref_data_t *ref = NULL;
            ref = (obj_ref_data_t *)hk_inode_get_slot(sih, (index << PAGE_SHIFT));
            blk_addr = get_pm_addr_by_data_ref(sbi, ref, (index << PAGE_SHIFT));
            if (DATA_IS_HOLE(ref->type)) { /* It's a file hole */
                zero = true;
            } else {
                dax_mem = blk_addr;
            }
            nr = (((u64)ref->num) - (index - (ref->ofs >> PAGE_SHIFT))) * HK_LBLK_SZ(sbi);
        } else {
            blk_addr = (u64)hk_inode_get_slot(sih, (index << PAGE_SHIFT));
            if (blk_addr == 0) { /* It's a file hole */
                zero = true;
            } else {
                dax_mem = blk_addr;
            }
            nr = nr <= HK_LBLK_SZ(sbi) ? nr : HK_LBLK_SZ(sbi);
        }

        nr = nr - offset;
        if (nr > len - copied)
            nr = len - copied;

        HK_START_TIMING(memcpy_r_nvmm_t, memcpy_time);

        hk_dbgv("%s: index: %d, blk_addr: 0x%llx, dax_mem: 0x%llx, zero: %d, nr: 0x%lx\n", __func__, index, blk_addr, dax_mem, zero, nr);

        num_readers = atomic64_add_return_relaxed(1, &sbi->num_readers);
        if (!zero) {
            win = rounddown_pow_of_two(ra_win / num_readers);
            hk_dbgv("win_size: %lu, num_readers: %d\n", win, num_readers);
            if (win != 0) {
                iter = nr & ~(win - 1);
                remain = nr & (win - 1);
                for (i = 0; i < iter; i += win) {
                    for (j = i; j < (i + win); j += 256) {
                        prefetcht2(dax_mem + offset + j);
                    }
                    left = __copy_to_user(buf + copied + i,
                                          dax_mem + offset + i, win);
                }
                if (remain) {
                    for (i = iter; i < nr; i += 256) {
                        prefetcht2(dax_mem + offset + i);
                    }
                    left = __copy_to_user(buf + copied + iter,
                                          dax_mem + offset + iter, remain);
                }
            } else {
                left = __copy_to_user(buf + copied,
                                      dax_mem + offset, nr);
            }

            /* prefetch per 256 */
            // for (i = 0; i < nr; i += 256) {
            //     prefetcht2(dax_mem + offset + i);
            // }
            // left = __copy_to_user(buf + copied,
            //                       dax_mem + offset, nr);
        } else {
            left = __clear_user(buf + copied, nr);
        }
        atomic64_fetch_sub_relaxed(1, &sbi->num_readers);

        HK_END_TIMING(memcpy_r_nvmm_t, memcpy_time);

        if (left) {
            hk_dbg("%s ERROR!: bytes %lu, left %lu\n",
                   __func__, nr, left);
            error = -EFAULT;
            goto out;
        }

        copied += nr;
        offset += nr;
        index += offset >> PAGE_SHIFT;
        offset &= ~PAGE_MASK;
    } while (copied < len);

out:
    *ppos = pos + copied;
    if (filp)
        file_accessed(filp);

    // hk_STATS_ADD(read_bytes, copied);
    hk_dbgv("%s returned %zu\n", __func__, copied);
    return copied ? copied : error;
}

static __always_inline bool hk_check_overlay(struct hk_inode_info *si, u64 index)
{
    bool is_overlay = false;
    struct hk_inode_info_header *sih = si->header;

    if (index < sih->ix.num_slots && (u64)hk_inode_get_slot(sih, (index << HUNTER_BLK_SHIFT)) != 0) {
        is_overlay = true;
    }

    return is_overlay;
}

/* check whether partial content can be written in the allocated block */
static __always_inline bool hk_check_inplace(loff_t pos, size_t len, size_t *written)
{
    bool is_inplace = false;
    loff_t end_pos = pos + len - 1;
    loff_t blk_start = _round_down(pos, HUNTER_BLK_SIZE);

    if (blk_start == pos) {
        *written = 0;
        return false;
    }

    *written = min(blk_start + HUNTER_BLK_SIZE - pos, len);

    return true;
}

static size_t hk_try_inplace_write(struct hk_inode_info *si, loff_t pos, size_t len, unsigned char *content)
{
    bool in_place = false;
    struct hk_inode_info_header *sih = si->header;
    struct super_block *sb = si->vfs_inode.i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    unsigned long irq_flags = 0;
    void *ref;
    size_t written = 0;

    in_place = hk_check_inplace(pos, len, &written);
    if (in_place) {
        ref = hk_inode_get_slot(sih, pos);
        if (!ref) {
            BUG_ON(1);
        }

        if (ENABLE_META_PACK(sb)) {
            obj_ref_data_t *ref_data = (obj_ref_data_t *)ref;
            void *target = get_pm_addr_by_data_ref(sbi, ref_data, pos);

            hk_memunlock_range(sb, target, HUNTER_BLK_SIZE, &irq_flags);
            memcpy_to_pmem_nocache(target, content, written);
            hk_memlock_range(sb, target, HUNTER_BLK_SIZE, &irq_flags);

            update_data_pkg(sbi, sih, get_pm_addr(sbi, ref_data->hdr.addr), 1, UPDATE_SIZE, pos + written);
        } else {
            /* Not support now */
            BUG_ON(1);
        }
    }

    return written;
}

static bool hk_try_perform_cow(struct hk_inode_info *si, u64 cur_addr, u64 index,
                               u64 start_index, u64 end_index,
                               loff_t each_ofs, size_t *each_size,
                               loff_t offset, size_t len)
{
    struct super_block *sb = si->vfs_inode.i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info_header *sih = si->header;
    bool is_overlay = false;
    u64 blk_addr;
    u32 blks_to_write = 0;
    unsigned long irq_flags = 0;
    INIT_TIMING(partial_time);

    HK_START_TIMING(partial_block_t, partial_time);
    is_overlay = hk_check_overlay(si, index);

    if (ENABLE_META_PACK(sb)) {
        if (is_overlay) {
            if (index == start_index) {
                if (each_ofs) {
                    obj_ref_data_t *ref = NULL;
                    ref = (obj_ref_data_t *)hk_inode_get_slot(sih, (index << PAGE_SHIFT));
                    blk_addr = get_pm_addr_by_data_ref(sbi, ref, (index << PAGE_SHIFT));
                    hk_memunlock_range(sb, cur_addr, each_ofs, &irq_flags);
                    memcpy_to_pmem_nocache(cur_addr, blk_addr, each_ofs);
                    hk_memlock_range(sb, cur_addr, each_ofs, &irq_flags);
                    *each_size -= each_ofs;
                }
            }
            blks_to_write = GET_ALIGNED_BLKNR(*each_size + each_ofs - 1);
            index += blks_to_write;
            /* possible addr of end_index */
            cur_addr += ((u64)blks_to_write << PAGE_SHIFT);
            if (index == end_index) {
                each_ofs = (offset + len) & (HK_LBLK_SZ(sbi) - 1);
                if (each_ofs) {
                    obj_ref_data_t *ref = NULL;
                    ref = (obj_ref_data_t *)hk_inode_get_slot(sih, offset + len);
                    if (ref) {
                        blk_addr = get_pm_addr_by_data_ref(sbi, ref, offset + len);
                        hk_memunlock_range(sb, cur_addr + each_ofs, HK_LBLK_SZ(sbi) - each_ofs, &irq_flags);
                        memcpy_to_pmem_nocache(cur_addr + each_ofs, blk_addr, HK_LBLK_SZ(sbi) - each_ofs);
                        hk_memlock_range(sb, cur_addr, HK_LBLK_SZ(sbi) - each_ofs, &irq_flags);
                    } else {
                        hk_memunlock_range(sb, cur_addr + each_ofs, HK_LBLK_SZ(sbi) - each_ofs, &irq_flags);
                        memset_nt(cur_addr + each_ofs, 0, HK_LBLK_SZ(sbi) - each_ofs);
                        hk_memlock_range(sb, cur_addr, HK_LBLK_SZ(sbi) - each_ofs, &irq_flags);
                    }
                    *each_size -= (HK_LBLK_SZ(sbi) - each_ofs);
                }
            }
        } else {
            if (index == start_index && each_ofs != 0) {
                hk_memunlock_range(sb, cur_addr, each_ofs, &irq_flags);
                memset_nt(cur_addr, 0, each_ofs);
                hk_memlock_range(sb, cur_addr, each_ofs, &irq_flags);
                *each_size -= each_ofs;
            }
            blks_to_write = GET_ALIGNED_BLKNR(*each_size + each_ofs - 1);
            index += blks_to_write;
            /* possible addr of end_index */
            cur_addr += ((u64)blks_to_write << PAGE_SHIFT);
            if (index == end_index) {
                each_ofs = (offset + len) & (HK_LBLK_SZ(sbi) - 1);
                if (each_ofs) {
                    hk_memunlock_range(sb, cur_addr + each_ofs, HK_LBLK_SZ(sbi) - each_ofs, &irq_flags);
                    memset_nt(cur_addr + each_ofs, 0, HK_LBLK_SZ(sbi) - each_ofs);
                    hk_memlock_range(sb, cur_addr, HK_LBLK_SZ(sbi) - each_ofs, &irq_flags);
                    *each_size -= (HK_LBLK_SZ(sbi) - each_ofs);
                }
            }
        }
    } else { /* 4KB  */
        if (is_overlay) {
            if (index == start_index || index == end_index) { /* Might perform cow */
                if (index == start_index && each_ofs != 0) {
                    blk_addr = (u64)hk_inode_get_slot(sih, (index << PAGE_SHIFT));
                    *each_size = min(HK_LBLK_SZ(sbi) - each_ofs, len);
                    hk_memunlock_range(sb, cur_addr, each_ofs, &irq_flags);
                    memcpy_to_pmem_nocache(cur_addr, hk_get_block(sb, blk_addr), each_ofs);
                    hk_memlock_range(sb, cur_addr, each_ofs, &irq_flags);
                }
                if (index == end_index && len < HK_LBLK_SZ(sbi)) {
                    blk_addr = (u64)hk_inode_get_slot(sih, (index << PAGE_SHIFT));
                    *each_size = len;
                    hk_memunlock_range(sb, cur_addr + (len + each_ofs), HK_LBLK_SZ(sbi) - (len + each_ofs), &irq_flags);
                    memcpy_to_pmem_nocache(cur_addr + (len + each_ofs), hk_get_block(sb, blk_addr) + (len + each_ofs), HK_LBLK_SZ(sbi) - (len + each_ofs));
                    hk_memlock_range(sb, cur_addr + (len + each_ofs), HK_LBLK_SZ(sbi) - (len + each_ofs), &irq_flags);
                }
            }
        } else { /* Set to zero */
            if (index == start_index && each_ofs != 0) {
                *each_size = min(HK_LBLK_SZ(sbi) - each_ofs, len);
                hk_memunlock_range(sb, cur_addr, each_ofs, &irq_flags);
                memset_nt(cur_addr, 0, each_ofs);
                hk_memlock_range(sb, cur_addr, each_ofs, &irq_flags);
            }
            if (index == end_index && len < HK_LBLK_SZ(sbi)) {
                *each_size = len;
                hk_memunlock_range(sb, cur_addr + (len + each_ofs), HK_LBLK_SZ(sbi) - (len + each_ofs), &irq_flags);
                memset_nt(cur_addr + (len + each_ofs), 0, HK_LBLK_SZ(sbi) - (len + each_ofs));
                hk_memlock_range(sb, cur_addr + (len + each_ofs), HK_LBLK_SZ(sbi) - (len + each_ofs), &irq_flags);
            }
        }
    }

    HK_END_TIMING(partial_block_t, partial_time);
    return is_overlay;
}

extern struct hk_mregion *hk_get_region_by_ino(struct super_block *sb, u64 ino);

static int do_perform_write(struct inode *inode, struct hk_layout_prep *prep,
                            loff_t ofs, size_t size, unsigned char *content,
                            u64 index_cur, u64 start_index, u64 end_index,
                            size_t *out_size)
{
    u64 i;
    int ret = 0;
    size_t each_size, aligned_each_size;
    loff_t each_ofs;
    u64 dst_blks, blks_prepared;
    u64 addr, addr_overlayed;
    bool is_overlay;
    struct super_block *sb = inode->i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    /* for background commit, i.e., async */
    struct hk_cmt_batch batch;
    /* for pack, i.e., write-once */
    in_pkg_param_t in_param;
    out_pkg_param_t out_param;
    unsigned long irq_flags = 0;
    char *buf;

    INIT_TIMING(memcpy_time);

    addr = prep->target_addr;
    blks_prepared = prep->blks_prepared;
    *out_size = 0;

    if (ENABLE_META_PACK(sb)) {
        each_ofs = ofs & (HK_LBLK_SZ(sbi) - 1);
        aligned_each_size = each_size = blks_prepared * HK_LBLK_SZ(sbi);
        is_overlay = hk_try_perform_cow(si, addr, index_cur,
                                        start_index, end_index,
                                        each_ofs, &each_size,
                                        ofs, size);
        HK_START_TIMING(memcpy_w_nvmm_t, memcpy_time);
        hk_memunlock_range(sb, addr + each_ofs, each_size, &irq_flags);
        if (likely(each_size >= HK_LBLK_SZ(sbi))) {
            memcpy_to_pmem_nocache(addr + each_ofs, content, each_size);
        } else {
            copy_from_user(addr + each_ofs, content, each_size);
            hk_flush_buffer(addr + each_ofs, each_size, false);
        }
        hk_memlock_range(sb, addr + each_ofs, each_size, &irq_flags);
        HK_END_TIMING(memcpy_w_nvmm_t, memcpy_time);

        in_param.bin = false;
        ret = create_data_pkg(sbi, sih, addr, (index_cur << PAGE_SHIFT), aligned_each_size, &in_param, &out_param);
        if (ret) {
            return ret;
        }

        *out_size = each_size;
    } else {
        struct hk_inode *pi = hk_get_inode(sb, inode);
        for (i = 0; i < prep->blks_prepared; i++) {
            each_size = HK_LBLK_SZ(sbi);
            each_ofs = ofs & (HK_LBLK_SZ(sbi) - 1);

            if (ENABLE_META_LOCAL(sb)) {
                if (i == 0 || i == prep->blks_prepared - 1) {
                    is_overlay = hk_try_perform_cow(si, addr, index_cur,
                                                    start_index, end_index,
                                                    each_ofs, &each_size,
                                                    ofs, size);

                    /* try prefetch hdr/region before writing it */
                    prefetcht2(sm_get_hdr_by_addr(sb, addr));
                    /* Prefetch Region */
                    /* prefetcht2((void *)hk_get_region_by_ino(sb, inode->i_ino)); */

                    HK_START_TIMING(memcpy_w_nvmm_t, memcpy_time);
                    hk_memunlock_range(sb, addr + each_ofs, each_size, &irq_flags);
                    /* Make sure Align 64 */
                    memcpy_to_pmem_nocache(addr + each_ofs, content, each_size);
                    hk_memlock_range(sb, addr + each_ofs, each_size, &irq_flags);
                    HK_END_TIMING(memcpy_w_nvmm_t, memcpy_time);

                    if (ENABLE_META_ASYNC(sb)) {
                        hk_valid_hdr_background(sb, inode, addr, index_cur);
                        if (is_overlay) {
                            addr_overlayed = TRANS_OFS_TO_ADDR(sbi, (u64)hk_inode_get_slot(sih, (index_cur << PAGE_SHIFT)));
                            hk_invalid_hdr_background(sb, inode, addr_overlayed, index_cur);
                        }
                    } else {
                        use_layout_for_addr(sb, addr);
                        sm_valid_hdr(sb, addr, sih->ino, index_cur, get_version(sbi));
                        unuse_layout_for_addr(sb, addr);
                        if (is_overlay) {
                            /* commit the inode */
                            hk_commit_newattr_indram(sb, inode);

                            addr_overlayed = TRANS_OFS_TO_ADDR(sbi, (u64)hk_inode_get_slot(sih, (index_cur << PAGE_SHIFT)));

                            /* invalid the old one */
                            use_layout_for_addr(sb, addr_overlayed);
                            sm_invalid_hdr(sb, addr_overlayed, sih->ino); /* Then invalid the old */
                            unuse_layout_for_addr(sb, addr_overlayed);

                            hk_dbgv("Invalid Blk %llu\n", hk_get_dblk_by_addr(sbi, addr_overlayed));
                        }
                    }

                    linix_insert(&sih->ix, index_cur, TRANS_ADDR_TO_OFS(sbi, addr), true);

                    addr += HK_PBLK_SZ(sbi);
                    index_cur += 1;
                } else {
                    if (prep->blks_prepared - 2 <= 0) {
                        continue;
                    } else {
                        dst_blks = prep->blks_prepared - 2;
                        each_size = (dst_blks * HK_LBLK_SZ(sbi));
                    }

                    HK_START_TIMING(memcpy_w_nvmm_t, memcpy_time);
                    hk_memunlock_range(sb, addr, each_size, &irq_flags);
                    memcpy_to_pmem_nocache(addr, content, each_size);
                    hk_memlock_range(sb, addr, each_size, &irq_flags);
                    HK_END_TIMING(memcpy_w_nvmm_t, memcpy_time);

                    /* minus 1 due to i++ in the for loop */
                    i += (dst_blks - 1);

                    hk_init_cmt_batch(sb, &batch, addr, index_cur, dst_blks);

                    while (dst_blks) {
                        is_overlay = hk_check_overlay(si, index_cur);

                        hk_inc_cmt_batch(sb, &batch);

                        if (ENABLE_META_ASYNC(sb)) {
                            /* do nothing */
                            if (is_overlay) {
                                hk_valid_range_background(sb, inode, &batch);
                                hk_next_cmt_batch(sb, &batch);

                                addr_overlayed = TRANS_OFS_TO_ADDR(sbi, (u64)hk_inode_get_slot(sih, (index_cur << PAGE_SHIFT)));
                                hk_invalid_hdr_background(sb, inode, addr_overlayed, index_cur);
                            }
                        } else {
                            use_layout_for_addr(sb, addr);
                            sm_valid_hdr(sb, addr, sih->ino, index_cur, get_version(sbi));
                            unuse_layout_for_addr(sb, addr);
                            if (is_overlay) {
                                hk_commit_newattr_indram(sb, inode);

                                addr_overlayed = TRANS_OFS_TO_ADDR(sbi, (u64)hk_inode_get_slot(sih, (index_cur << PAGE_SHIFT)));
                                /* invalid the old one */
                                use_layout_for_addr(sb, addr_overlayed);
                                sm_invalid_hdr(sb, addr_overlayed, sih->ino); /* Then invalid the old */
                                unuse_layout_for_addr(sb, addr_overlayed);

                                hk_dbgv("Invalid Blk %llu\n", hk_get_dblk_by_addr(sbi, addr_overlayed));
                            }
                        }

                        linix_insert(&sih->ix, index_cur, TRANS_ADDR_TO_OFS(sbi, addr), true);

                        dst_blks -= 1;

                        addr += HK_PBLK_SZ(sbi);
                        index_cur += 1;
                    }

                    if (ENABLE_META_ASYNC(sb)) {
                        if (hk_is_cmt_batch_valid(sb, &batch)) {
                            hk_valid_range_background(sb, inode, &batch);
                        }
                    }
                }
            } else { /* Default is LFS */
                is_overlay = hk_try_perform_cow(si, addr, index_cur,
                                                start_index, end_index,
                                                each_ofs, &each_size,
                                                ofs, size);

                HK_START_TIMING(memcpy_w_nvmm_t, memcpy_time);
                hk_memunlock_range(sb, addr + each_ofs, each_size, &irq_flags);
                memcpy_to_pmem_nocache(addr + each_ofs, content, each_size);
                hk_memlock_range(sb, addr + each_ofs, each_size, &irq_flags);
                HK_END_TIMING(memcpy_w_nvmm_t, memcpy_time);

                if (ENABLE_META_ASYNC(sb)) {
                    hk_valid_hdr_background(sb, inode, addr, index_cur);
                    if (is_overlay) {
                        addr_overlayed = TRANS_OFS_TO_ADDR(sbi, (u64)hk_inode_get_slot(sih, (index_cur << PAGE_SHIFT)));
                        hk_invalid_hdr_background(sb, inode, addr_overlayed, index_cur);
                    }
                } else {
                    use_layout_for_addr(sb, addr);
                    sm_valid_hdr(sb, addr, sih->ino, index_cur, get_version(sbi));
                    unuse_layout_for_addr(sb, addr);
                    if (is_overlay) {
                        hk_commit_newattr_indram(sb, inode);

                        addr_overlayed = TRANS_OFS_TO_ADDR(sbi, (u64)hk_inode_get_slot(sih, (index_cur << PAGE_SHIFT)));

                        /* invalid the old one */
                        use_layout_for_addr(sb, addr_overlayed);
                        sm_invalid_hdr(sb, addr_overlayed, sih->ino); /* Then invalid the old */
                        unuse_layout_for_addr(sb, addr_overlayed);

                        hk_dbgv("Invalid Blk %llu\n", hk_get_dblk_by_addr(sbi, addr_overlayed));
                    }
                }

                linix_insert(&sih->ix, index_cur, TRANS_ADDR_TO_OFS(sbi, addr), true);

                addr += HK_PBLK_SZ(sbi);
                index_cur += 1;
            }

            content += each_size;
            ofs += each_size;
            size -= each_size;
            *out_size += each_size;
        }
    }

    return 0;
}

ssize_t do_hk_file_write(struct file *filp, const char __user *buf,
                         size_t len, loff_t *ppos)
{
    struct inode *inode = filp->f_mapping->host;
    struct super_block *sb = inode->i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    pgoff_t index, start_index, end_index, i;
    unsigned long blks;
    loff_t pos, fsize;
    size_t copied = 0;
    ssize_t written = 0;
    size_t error = 0;
    u64 allocated;
    u64 addr;
    unsigned long irq_flags = 0;
    unsigned char *pbuf = buf;
    struct hk_layout_prep prep;
    struct hk_layout_prep *pprep;
    size_t out_size = 0;
    bool append_like = false;
    int ret = 0;

    INIT_TIMING(write_time);
    INIT_TIMING(memcpy_time);

    if (len == 0)
        return 0;

    HK_START_TIMING(write_t, write_time);

    if (!access_ok(buf, len)) {
        error = -EFAULT;
        goto out;
    }

    pos = *ppos;

    if (filp->f_flags & O_APPEND) {
        append_like = true;
        pos = i_size_read(inode);
    }

    if (pos == i_size_read(inode)) {
        append_like = true;
    }

    error = file_remove_privs(filp);
    if (error)
        goto out;

    /* if append write, i.e., pos == file size, try to perform in-place write */
    if (append_like) {
        out_size = hk_try_inplace_write(si, pos, len, pbuf);

        pos += out_size;
        len -= out_size;
        pbuf += out_size;
        written += out_size;
    }

    out_size = 0;

    start_index = index = pos >> PAGE_SHIFT;   /* Start from which blk */
    end_index = (pos + len - 1) >> PAGE_SHIFT; /* End till which blk */
    blks = (end_index - index + 1);            /* Total blks to be written */

    inode->i_ctime = inode->i_mtime = current_time(inode);

    hk_dbgv("%s: inode %lu, offset %lld, size %lu, blks %lu\n",
            __func__, inode->i_ino, pos, len, blks);

    if (len != 0) {
        while (index <= end_index) {
            ret = hk_alloc_blocks(sb, &blks, false, &prep);
            if (ret) {
                hk_dbg("%s alloc blocks failed %d\n", __func__, ret);
                goto out;
            }

            do_perform_write(inode, &prep, pos, len, pbuf,
                             index, start_index, end_index,
                             &out_size);

            pos += out_size;
            len -= out_size;
            pbuf += out_size;
            written += out_size;

            index += prep.blks_prepared;
        }
    }

    sih->i_blocks = end_index + 1;

    inode->i_blocks = sih->i_blocks;

    hk_dbgv("%s: len %lu\n",
            __func__, len);

    *ppos = pos;
    if (pos > inode->i_size) {
        i_size_write(inode, pos);
        sih->i_size = pos;
    }

out:
    if (ENABLE_META_ASYNC(sb)) {
        /* do nothing */
    } else {
        if (ENABLE_META_PACK(sb)) {
            /* Write-Once */
            /* do nothing */
        } else {
            hk_commit_newattr_indram(sb, inode);
        }
    }

    HK_END_TIMING(write_t, write_time);
    return written ? written : error;
}

/* ======================= ANCHOR hooks ========================= */

static loff_t hk_llseek(struct file *file, loff_t offset, int whence)
{
    struct inode *inode = file->f_path.dentry->d_inode;
    int retval;

    if (whence != SEEK_DATA && whence != SEEK_HOLE)
        return generic_file_llseek(file, offset, whence);

    return -ENOTSUPP;
}

/*
 * Wrappers. We need to use the rcu read lock to avoid
 * concurrent truncate operation. No problem for write because we held
 * lock.
 */
static ssize_t hk_dax_file_read(struct file *filp, char __user *buf,
                                size_t len, loff_t *ppos)
{
    struct inode *inode = filp->f_mapping->host;
    ssize_t res;
    INIT_TIMING(dax_read_time);

    HK_START_TIMING(dax_read_t, dax_read_time);
    inode_lock_shared(inode);

    res = do_dax_mapping_read(filp, buf, len, ppos);

    inode_unlock_shared(inode);
    HK_END_TIMING(dax_read_t, dax_read_time);
    return res;
}

static ssize_t hk_dax_file_write(struct file *filp, const char __user *buf,
                                 size_t len, loff_t *ppos)
{
    struct address_space *mapping = filp->f_mapping;
    struct inode *inode = mapping->host;
    int ret;

    if (len == 0)
        return 0;

    sb_start_write(inode->i_sb);
    inode_lock(inode);

    ret = do_hk_file_write(filp, buf, len, ppos);

    inode_unlock(inode);
    sb_end_write(inode->i_sb);

    return ret;
}

static int hk_open(struct inode *inode, struct file *filp)
{
    return generic_file_open(inode, filp);
}

/* This function is called by both msync() and fsync(). */
static int hk_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
    struct address_space *mapping = file->f_mapping;
    struct inode *inode = file->f_path.dentry->d_inode;
    struct super_block *sb = inode->i_sb;
    int ret = 0;
    INIT_TIMING(fsync_time);

    HK_START_TIMING(fsync_t, fsync_time);

    ret = generic_file_fsync(file, start, end, datasync);
    if (ENABLE_META_ASYNC(sb)) {
        hk_flush_cmt_inode_fast(sb, inode->i_ino);
    }

persist:
    PERSISTENT_BARRIER();
    HK_END_TIMING(fsync_t, fsync_time);

    return ret;
}

static ssize_t hk_rw_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    struct file *filp = iocb->ki_filp;
    struct inode *inode = filp->f_mapping->host;
    ssize_t ret = -EIO;
    ssize_t written = 0;
    unsigned long seg;
    unsigned long nr_segs = iter->nr_segs;
    const struct iovec *iv = iter->iov;
    INIT_TIMING(wrap_iter_time);

    HK_START_TIMING(wrap_iter_t, wrap_iter_time);

    hk_dbgv("%s %s: %lu segs\n", __func__,
            iov_iter_rw(iter) == READ ? "read" : "write",
            nr_segs);

    if (iov_iter_rw(iter) == WRITE) {
        sb_start_write(inode->i_sb);
        inode_lock(inode);
    } else {
        inode_lock_shared(inode);
    }

    iv = iter->iov;
    for (seg = 0; seg < nr_segs; seg++) {
        if (iov_iter_rw(iter) == READ) {
            ret = do_dax_mapping_read(filp, iv->iov_base,
                                      iv->iov_len, &iocb->ki_pos);
        } else if (iov_iter_rw(iter) == WRITE) {
            ret = do_hk_file_write(filp, iv->iov_base,
                                   iv->iov_len, &iocb->ki_pos);
        } else {
            BUG();
        }
        if (ret < 0)
            goto err;

        if (iter->count > iv->iov_len)
            iter->count -= iv->iov_len;
        else
            iter->count = 0;

        written += ret;
        iter->nr_segs--;
        iv++;
    }
    ret = written;
err:
    if (iov_iter_rw(iter) == WRITE) {
        inode_unlock(inode);
        sb_end_write(inode->i_sb);
    } else {
        inode_unlock_shared(inode);
    }

    HK_END_TIMING(wrap_iter_t, wrap_iter_time);
    return ret;
}

/* This callback is called when a file is closed */
static int hk_flush(struct file *file, fl_owner_t id)
{
    /* TODO: we should move some routines in evict inode here ? */
    PERSISTENT_BARRIER();
    return 0;
}

const struct inode_operations hk_file_inode_operations = {
    .setattr = hk_notify_change,
    .getattr = hk_getattr,
    .get_acl = NULL,
};

const struct file_operations hk_dax_file_operations = {
    .llseek = hk_llseek,
    .read = hk_dax_file_read,
    .write = hk_dax_file_write,
    .read_iter = hk_rw_iter,
    .write_iter = hk_rw_iter,
    .mmap = NULL, /* TODO: Not support mmap yet */
    .mmap_supported_flags = MAP_SYNC,
    .open = hk_open,
    .fsync = hk_fsync,
    .flush = hk_flush,
    .unlocked_ioctl = hk_ioctl,
    .fallocate = NULL, /* TODO: Not support yet */
#ifdef CONFIG_COMPAT
    .compat_ioctl = hk_compat_ioctl,
#endif
};