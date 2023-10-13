/*
 * HUNTER Recovery routines.
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

int hk_save_layouts(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_super_block *hk_sb = sbi->hk_sb;
    struct hk_layout_info *layout;
    int ret = 0;
    int cpuid;

    for (cpuid = 0; cpuid < sbi->num_layout; cpuid++) {
        layout = &sbi->layouts[cpuid];

        if (layout->ind.prep_blks != 0) {
            hk_dump_layout_info(layout);
        }

        hk_sb->s_layout->s_atomic_counter = cpu_to_le64(layout->atomic_counter);

        hk_sb->s_layout->s_ind.free_blks = cpu_to_le64(layout->ind.free_blks);
        hk_sb->s_layout->s_ind.invalid_blks = cpu_to_le64(layout->ind.invalid_blks);
        hk_sb->s_layout->s_ind.prep_blks = cpu_to_le64(layout->ind.prep_blks);
        HK_ASSERT(hk_sb->s_layout->s_ind.prep_blks == 0);
        hk_sb->s_layout->s_ind.valid_blks = cpu_to_le64(layout->ind.valid_blks);
        hk_sb->s_layout->s_ind.total_blks = cpu_to_le64(layout->ind.total_blks);
    }

    hk_update_super_crc(sb);

    hk_sync_super(sb);
    hk_info("layouts dumped OK\n");
    return ret;
}

/* Apply all regions to inode */
int hk_save_regions(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_attr_log *al;
    int alid;

    for (alid = 0; alid < sbi->al_slots; alid++) {
        al = hk_get_attr_log_by_alid(sb, alid);
        if (le64_to_cpu(al->ino) != (u64)-1) {
            hk_evicting_attr_log(sb, al);
        }
    }
    hk_info("attr dumps OK\n");

    return 0;
}

static int hk_inode_recovery_from_jentry(struct super_block *sb, struct hk_jentry *je)
{
    struct hk_inode *pi;

    // TODO: Fine-grain inode recovery
    return 0;
}

static int hk_inode_recovery(struct super_block *sb, struct hk_inode *pi, struct hk_jentry *je_pi,
                             bool create, bool invalidate)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    unsigned long irq_flags = 0;

    // TODO: Fine-grain inode recovery
    return 0;
}

static int hk_dentry_recovery(struct super_block *sb, u64 dir_ino, struct hk_jentry *je_pd, bool invalidate)
{
    struct inode *dir;
    const char *name;
    int name_len;
    u64 ino;
    u16 link_change = 0;

    // TODO: Fine-grain dentry recovery
    return 0;
}

/* Re-do Recovery (Redo Journal) */
static int hk_journal_recovery(struct super_block *sb, int txid, struct hk_journal *jnl)
{
    int ret = 0;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_jentry *je_pi;
    struct hk_jentry *je_pd;
    struct hk_jentry *je_pd_new;
    struct hk_jentry *je_pi_par;
    struct hk_jentry *je_pi_new;
    struct hk_jentry *je_pd_sym; /* only for symlink */

    struct hk_inode *pi;

    struct inode *dir, *inode;
    const char *symname;
    int symlen;
    unsigned long irq_flags = 0;
    u8 jtype = jnl->jhdr.jtype;

    // TODO: Fine-grain journal recovery

    hk_finish_tx(sb, txid);
out:
    return ret;
}

int hk_failure_recovery(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_super_block *hk_sb = sbi->hk_sb;
    struct hk_layout_info *layout;
    struct hk_journal *jnl;
    struct hk_attr_log *al;
    struct hk_header *hdr;
    struct hk_inode *pi;
    u64 not_free_blks = 0;
    u64 blk = 0;
    u64 addr = 0;
    int cpuid, alid, txid;
    unsigned long irq_flags = 0;

    /* Revisiting Meta Regions Here */
    for (alid = 0; alid < sbi->al_slots; alid++) {
        al = hk_get_attr_log_by_alid(sb, alid);
        if (al->evicting || le64_to_cpu(al->ino) != (u64)-1) {
            hk_evicting_attr_log(sb, al);
        }
    }

    /* Recovery Layouts And Indicators Here */
    for (cpuid = 0; cpuid < sbi->num_layout; cpuid++) {
        layout = &sbi->layouts[cpuid];
        not_free_blks = 0;
        blk = 0;

        use_layout(layout);
        layout->atomic_counter = (layout->layout_blks * HK_PBLK_SZ);
        ind_update(&layout->ind, PREP_LAYOUT_APPEND, layout->layout_blks);

        traverse_layout_blks(addr, layout)
        {
            hdr = sm_get_hdr_by_addr(sb, addr);
            if (hdr->valid) {
                pi = hk_get_inode_by_ino(sb, hdr->ino);
                /* Remove The Invalid Hdr */
                if (!pi->valid || hdr->tstamp > pi->tstamp) {
                    hk_memunlock_hdr(sb, hdr, &irq_flags);
                    hdr->valid = 0;
                    hk_memlock_hdr(sb, hdr, &irq_flags);

                    sm_remove_hdr(sb, (void *)pi, hdr);
                    ind_update(&layout->ind, PREP_LAYOUT_REMOVE, 1);
                } else { /* Re insert */
                    sbi->tstamp = le64_to_cpu(pi->tstamp);
                    not_free_blks = blk + 1;

                    sm_remove_hdr(sb, (void *)pi, hdr);
                    sm_insert_hdr(sb, (void *)pi, hdr);
                    ind_update(&layout->ind, VALIDATE_BLK, 1);
                }
            } else {
                ind_update(&layout->ind, PREP_LAYOUT_REMOVE, 1);
            }
            blk++;
        }
        hk_release_layout(sb, cpuid, layout->layout_blks - not_free_blks, false);
        unuse_layout(layout);
    }

    /* Redo Journal Here */
    for (txid = 0; txid < sbi->j_slots; txid++) {
        jnl = hk_get_journal_by_txid(sb, txid);
        if (jnl->jhdr.jofs_head != jnl->jhdr.jofs_tail) {
            hk_journal_recovery(sb, txid, jnl);
        }
    }

    return 0;
}

static bool hk_try_normal_recovery(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_super_block *super = sbi->hk_sb;
    struct hk_layout_info *layout;
    bool is_failure = false;
    int cpuid;

    if (le32_to_cpu(super->s_valid_umount) == HK_VALID_UMOUNT) {
        hk_dbgv("normal recovery\n");
        sbi->tstamp = le64_to_cpu(super->s_tstamp);
        for (cpuid = 0; cpuid < sbi->num_layout; cpuid++) {
            layout = &sbi->layouts[cpuid];
            layout->atomic_counter = le64_to_cpu(super->s_layout->s_atomic_counter);

            layout->ind.free_blks = le64_to_cpu(super->s_layout->s_ind.free_blks);
            layout->ind.invalid_blks = le64_to_cpu(super->s_layout->s_ind.invalid_blks);
            layout->ind.prep_blks = le64_to_cpu(super->s_layout->s_ind.prep_blks);
            layout->ind.valid_blks = le64_to_cpu(super->s_layout->s_ind.valid_blks);
            layout->ind.total_blks = le64_to_cpu(super->s_layout->s_ind.total_blks);
        }
        goto out;
    } else {
        is_failure = true;
    }
out:
    return is_failure;
}
/*
 * Recovery routine has two tasks:
 * 1. Restore Per Layout Tail;
 * 2. Restore Indicators;
 */
int hk_recovery(struct super_block *sb)
{
    bool is_failure = false;

    INIT_TIMING(start);

    hk_dbgv("%s\n", __func__);

    HK_START_TIMING(recovery_t, start);

    is_failure = hk_try_normal_recovery(sb);

    if (!is_failure) {
        hk_dbg("HUNTER: Normal shutdown\n");
    } else {
        hk_failure_recovery(sb);
    }

    HK_END_TIMING(recovery_t, start);

    return 0;
}
