/*
 * HUNTER Self GC and Eqalizer impl.
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

wait_queue_head_t  gc_finish_wq;
int                *gc_finished;

wait_queue_head_t  eq_finish_wq;
int                eq_finished;

static void wait_to_finish_eq(void)
{
    while(eq_finished == 0) {
        wait_event_interruptible_timeout(eq_finish_wq, false, 
                                         msecs_to_jiffies(1));
    }
}

static void wait_to_finish_gc(int cpus)
{
	int cpuid;

	for (cpuid = 0; cpuid < cpus; cpuid++) {
		while (gc_finished[cpuid] == 0) {
			wait_event_interruptible_timeout(gc_finish_wq, false,
							                 msecs_to_jiffies(1));
		}
	}
}

static int hk_update_dir_table_for_blk(struct super_block *sb, u64 f_blk, struct hk_inode_info_header *sih)
{
	struct hk_sb_info *sbi = HK_SB(sb);
	struct hk_dentry  *direntry;
	u16 			  i;
	u64			 	  blk_addr;		
	
    for (i = 0; i < MAX_DENTRY_PER_BLK; i++)
	{
		blk_addr = TRANS_OFS_TO_ADDR(sbi, linix_get(&sih->ix, f_blk));
		direntry = hk_dentry_by_ix_from_blk(blk_addr, i);
		if (direntry->valid) 
		{
			hk_update_dir_table(sb, sih, direntry->name, direntry->name_len, direntry);
		}
	}

    return 0;
}

enum hk_blk_type
{
    DATA_BLK,           /* Inode Blk */
    DENT_BLK,           /* Dentry Blk */
    SPEC_BLK            /* Special Blk */
};

enum hk_blk_type hk_get_blk_type_by_inode(struct hk_inode *pi)
{
    switch (__le16_to_cpu(pi->i_mode) & S_IFMT) {
    case S_IFREG:
        return DATA_BLK;
    case S_IFDIR:
        return DENT_BLK;
    default:
        return SPEC_BLK;
	}
}

int hk_try_update_dram(struct super_block *sb, u64 srvv_addr, struct hk_header *vict_hdr, 
                       enum hk_blk_type type)
{
    struct inode         *inode;
    struct hk_inode_info_header *sih;
    u64                  vict_addr;
    struct hk_sb_info    *sbi = HK_SB(sb);
    u64 ino;
    int ret = -1;
    
    ino = vict_hdr->ino;
    inode = hk_iget_opened(sb, ino);
    vict_addr = TRANS_ADDR_TO_OFS(sbi, sm_get_addr_by_hdr(sb, vict_hdr));
    if (inode) {
        sih = HK_IH(inode);
        /* Although the victim blocks are valid, it might have been deleted 
           by caller (e.g. truncate), because we have cmt system, we can't 
           delete blocks directly, we must send other invalid request to the 
           cmt queue. In that case, the block in NVM still remains valid.

           GC system (equlizer) finds that the block is valid, then will 
           migrate it. However, the victim block is not valid anymore, so 
           we should never index it back to our upper file. By calling:

                linix_get(&sih->ix, vict_hdr->f_blk) == vict_addr

           we can verify whether the block is still visible to upper file, 
           and only if it is, we can change the index of it back to our 
           upper file. Or the current file will be corrupted by obstale 
           data which is blamed to Equlizer. 

           Incorrect handle of this situation causes a severe BUG in our 
           cmt system, take GC-Mechinsm as an example.
           
                forloop() {
                        write()
                        truncate()
                }

           1. The write() will write the data A to layout a, and index it 
              in our file (at 0).
           2. The truncate() happens, and the data A is to be 
              invalidated, we remove index of A.
           3. The write() is then called. It writes data B to layout b, and 
              updates corresponding index (at 0).
           4. GC is called, and it finds that the data A is valid, and it migrates
              A back in layout a. At this time, if we change the index, then 
              the file is corrupted by an invalid block A, and leads to problems 
              in consecutive truncate(). (Invalid the same block twice, see annotation 
              in cmt.c line 180 -- 185). But the problems should never happen 
              in GC-Mechanism workload.

              The cmt system is blamed to this. The state of block can immediately 
              be visible to upper caller (e.g. file), but is blind to lower layer workers 
              (gc migration). So we should do the check below to make sure the 
              consistency of NVM and DRAM.       
        */
        if (linix_get(&sih->ix, vict_hdr->f_blk) == vict_addr) {
            switch (type)
            {
            case SPEC_BLK:
            case DATA_BLK:
                linix_insert(&sih->ix, vict_hdr->f_blk, srvv_addr, true);
                break;
            case DENT_BLK:
                linix_insert(&sih->ix, vict_hdr->f_blk, srvv_addr, true);
                hk_update_dir_table_for_blk(sb, vict_hdr->f_blk, sih);
                break;
            default:
                break;
            }
        }
        iput(inode);
        ret = 0;
    }

    return ret;
}

#if 0
u64 hk_try_write_vict(struct super_block *sb, int cpuid, u64 vict_addr, enum hk_layout_type layout_type)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_layout_info *layout;
    bool opened = false;
    u64  suvv_addr = 0;
    unsigned long irq_flags = 0;
    
    layout = &sbi->layouts[cpuid];

    switch (layout_type)
    {
    case LAYOUT_APPEND:
        break;
    case LAYOUT_GAP:
        use_layout(layout);
        suvv_addr = hk_prepare_layout(sb, cpuid, 1, LAYOUT_GAP, NULL, false);
        if (!suvv_addr) {
            unuse_layout(layout);
            return 0;
        }
        unuse_layout(layout);
        break;
    default:
        break;
    } 

    hk_memunlock_range(sb, suvv_addr, HK_LBLK_SZ, &irq_flags);
    memcpy_to_pmem_nocache(suvv_addr, vict_addr, HK_LBLK_SZ);
    hk_memlock_range(sb, suvv_addr, HK_LBLK_SZ, &irq_flags);
    
    return suvv_addr;
}
#endif

u64 hk_try_write_vict_no_lock(struct super_block *sb, int cpuid, u64 vict_addr, enum hk_layout_type layout_type)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_layout_info *layout;
    bool opened = false;
    u64  suvv_addr = 0;
    unsigned long irq_flags = 0;
    
    layout = &sbi->layouts[cpuid];

    switch (layout_type)
    {
    case LAYOUT_APPEND:
        break;
    case LAYOUT_GAP:
        suvv_addr = hk_prepare_layout(sb, cpuid, 1, LAYOUT_GAP, NULL, false);
        if (!suvv_addr) {
            return 0;
        }
        break;
    default:
        break;
    } 

    hk_memunlock_range(sb, suvv_addr, HK_LBLK_SZ, &irq_flags);
    memcpy_to_pmem_nocache(suvv_addr, vict_addr, HK_LBLK_SZ);
    hk_memlock_range(sb, suvv_addr, HK_LBLK_SZ, &irq_flags);
    
    return suvv_addr;
}

static u64 hk_drop_latest_gap(struct super_block *sb, int cpuid)
{
    struct hk_sb_info     *sbi = HK_SB(sb);
    struct hk_layout_info *layout;
    struct hk_range_node  *cur;
    struct list_head 	  *pos, *q;
    u64                   gaps_to_drop = 0;

    layout = &sbi->layouts[cpuid];

    if (likely(!list_empty(&layout->gaps_list))) {
        list_for_each_safe(pos, q, &layout->gaps_list) {
            cur = list_entry(pos, struct hk_range_node, node);
            list_del(pos);
            hk_free_range_node(cur);
            gaps_to_drop = cur->high - cur->low + 1;
            break;
        }
        layout->num_gaps_indram -= gaps_to_drop;
    }

    return gaps_to_drop;
}

#if 0
static void hk_try_use_layout_for_srvv(struct super_block *sb, int from, int to, u64 srvv_addr)
{
    if (from != to) 
        use_layout_for_addr(sb, srvv_addr);
}

static void hk_try_unuse_layout_for_srvv(struct super_block *sb, int from, int to, u64 srvv_addr)
{
    if (from != to) 
        unuse_layout_for_addr(sb, srvv_addr);
}
#endif

/* make sure from layout's and to layout's lock is held */
int hk_try_write_back(struct super_block *sb, int from, int to)
{
    struct inode          *inode;
    struct hk_sb_info     *sbi = HK_SB(sb);
    struct hk_layout_info *from_layout;
    struct hk_layout_info *to_layout; 
    struct hk_header      *vict_hdr;
    struct hk_inode       *pi;
    struct hk_range_node  *latest_gap;
    enum hk_blk_type      blk_type;
    u64 blks;
    u64 gaps_to_drop = 0;
    u64 blks_to_rls = 0;
    u64 vict_addr, srvv_addr;
    int ret;

    from_layout = &sbi->layouts[from];
    to_layout = &sbi->layouts[to];
    
    vict_addr = GET_LAST_BLK_FROM_LAYOUT(from_layout);

    if (hk_range_find_value(sb, &from_layout->prep_list, hk_get_dblk_by_addr(sbi, vict_addr))) {
        return -1;
    }

    vict_hdr = sm_get_hdr_by_addr(sb, vict_addr);
    
    /* write victim back */
    if (vict_hdr->valid) {
        pi = hk_get_inode_by_ino(sb, vict_hdr->ino);
        blk_type = hk_get_blk_type_by_inode(pi);
        
        srvv_addr = hk_try_write_vict_no_lock(sb, to, vict_addr, LAYOUT_GAP);
        
        hk_dbgv("%s: migrate victim 0x%llx from %d to %d, srvv_addr 0x%llx\n", __func__, vict_addr, from, to, srvv_addr);
        
        if (srvv_addr) {
            ret = hk_try_update_dram(sb, srvv_addr, vict_hdr, blk_type);
        }
        else {
            return -ENOSPC;
        }

        use_nvm_inode(sb, vict_hdr->ino);
        sm_valid_hdr(sb, srvv_addr, vict_hdr->ino, vict_hdr->f_blk, get_version(sbi));
        hk_commit_newattr(sb, pi->ino);
        sm_invalid_hdr(sb, vict_addr, vict_hdr->ino);
        unuse_nvm_inode(sb, vict_hdr->ino);

        blks_to_rls = 1;
    }

    /* rls layout */
    hk_find_gaps(sb, from);
    latest_gap = list_first_entry(&from_layout->gaps_list, struct hk_range_node, node);
    if (latest_gap) {
        if (latest_gap->high + 1 == hk_get_dblk_by_addr(sbi, vict_addr)) {
            /* the gaps are not built, vict_blk is not visible to gaps_list  */
            gaps_to_drop = hk_drop_latest_gap(sb, from);
            blks_to_rls += gaps_to_drop;
        }
        else if (latest_gap->high == hk_get_dblk_by_addr(sbi, vict_addr)) {
            /* the gaps are not rebuilt, vict_blk is now visible to gaps_list  */
            /* or vict_blk is invalid  */
            gaps_to_drop = hk_drop_latest_gap(sb, from);
            blks_to_rls = gaps_to_drop;
        }
    }

    hk_release_layout(sb, from, blks_to_rls, false);
    
    return 0;
}

struct hk_gc_self_param
{
    struct super_block    *sb;
    struct hk_layout_info *layout;
};

static int hk_self_gc_thread(void *arg)
{
    struct hk_gc_self_param *param = arg;
    struct super_block      *sb = param->sb;
    struct hk_layout_info   *layout = param->layout;
    int ret = 0;
    int retries = 0;
    int cpuid = layout->cpuid;
    u64 blks_original = 0;
    u64 blks_after_migration = 0;

    INIT_TIMING(migrate_time);

retry:
    use_layout(layout);
    retries++;
    for(;;) {
        if (!layout->ind.invalid_blks || layout->atomic_counter == 0) {
            break;
        }
        HK_START_TIMING(self_gc_migrates_t, migrate_time);
        blks_original = layout->atomic_counter / HK_PBLK_SZ;
        ret = hk_try_write_back(sb, cpuid, cpuid);
        blks_after_migration = layout->atomic_counter / HK_PBLK_SZ;
        HK_STATS_ADD(self_gc_migrated_blocks, blks_original - blks_after_migration);
        HK_END_TIMING(self_gc_migrates_t, migrate_time);
        if (ret) {
            if (retries > HK_MAX_GC_ATTEMPTS) {
                break;
            }
            unuse_layout(layout);
            retries++;
            /* time out 1s */
            schedule_timeout(1 * HZ);
            goto retry;
        }
    }
    
    unuse_layout(layout);

    gc_finished[cpuid] = 1;
	wake_up_interruptible(&gc_finish_wq);
    do_exit(ret);
	return ret;
}

int hk_do_self_gc(struct super_block *sb)
{
    struct hk_sb_info       *sbi = HK_SB(sb);
    struct hk_layout_info   *layout;
    struct hk_gc_self_param *params;
    struct hk_gc_self_param *param;
    
    int cpuid;
    int ret = 0;
    
    params = kvmalloc(sizeof(struct hk_gc_self_param) * sbi->num_layout, GFP_KERNEL);
    if (!params) {
        ret = -ENOMEM;
        goto out;
    }

    gc_finished = kcalloc(sbi->num_layout, sizeof(int), GFP_KERNEL);
	if (!gc_finished) {
        ret = -ENOMEM;
		goto fail1;
    }

    init_waitqueue_head(&gc_finish_wq);

    for (cpuid = 0; cpuid < sbi->num_layout; cpuid++) {
        layout = &sbi->layouts[cpuid];
        param = &params[cpuid];
        param->sb = sb;
        param->layout = layout;

        layout->self_gc_thread = kthread_create(hk_self_gc_thread, param, 
                                                "hk_self_gc_thread_%d", cpuid);
        kthread_bind(layout->self_gc_thread, cpuid);
        
        wake_up_process(layout->self_gc_thread);
    }

    wait_to_finish_gc(sbi->num_layout);

    kfree(gc_finished);
fail1:
    kvfree(params);
out:
    return ret;
}

int hk_friendly_gc(struct super_block *sb) 
{
    for (;;) {
        if (try_up_gc(sb)) {
            break;
        }
    }

    hk_do_self_gc(sb);

    down_gc(sb);
    hk_info("friendly gc finished\n");
    return 0;
}

/* ======================= ANCHOR: Equlizer ========================= */
// int hk_do_layout_equalize(struct super_block *sb) 
// {
//     struct hk_sb_info     *sbi = HK_SB(sb);
//     struct hk_layout_info *layout;
//     u64 blks_original = 0;
//     u64 blks_after_migration = 0;
//     int cpuid;
//     INIT_TIMING(migrate_time);

//     for (cpuid = 0; cpuid < sbi->num_layout; cpuid++) {
//         layout = &sbi->layouts[cpuid];
//         use_layout(layout);
//         if (layout->ind.invalid_blks) {
//             if (try_up_gc(sb)) {
//                 hk_dbgv("%s called\n", __func__);
//                 HK_START_TIMING(equalizer_migrates_t, migrate_time);
//                 blks_original = layout->atomic_counter / HK_PBLK_SZ;
//                 hk_try_write_back(sb, cpuid, cpuid);
//                 blks_after_migration = layout->atomic_counter / HK_PBLK_SZ;
//                 HK_STATS_ADD(equalizer_migrated_blocks, blks_original - blks_after_migration);
//                 HK_END_TIMING(equalizer_migrates_t, migrate_time);
//                 down_gc(sb);
//             }
//         }
//         unuse_layout(layout);
//     }

//     return 0;
// }

// static int hk_layout_equalizer_thread(void *arg)
// {
//     struct super_block *sb = arg;
//     struct hk_sb_info  *sbi = HK_SB(sb);
    
//     allow_signal(SIGINT);
    
//     for (;;) {
//         ssleep_interruptible(HK_EQU_TIME_GAP);

//         if (kthread_should_stop()) {
//             break;
//         }
        
//         hk_do_layout_equalize(sb);
        
//         /* Be Nice */
//         cond_resched();
//     }
    
//     flush_signals(current);

//     eq_finished = 1;
//     wake_up_interruptible(&eq_finish_wq);
//     return 0;
// }

// // TODO: wait to finish
// int hk_start_equalizer(struct super_block *sb)
// {   
//     struct hk_sb_info *sbi = HK_SB(sb);
    
    
//     sbi->layout_equalizer_thread = kthread_run(hk_layout_equalizer_thread, 
//                                                 sb, "hk_layout_equalizer_thread");
//     if (IS_ERR(sbi->layout_equalizer_thread)) {
//         hk_info("Failed to start HUNTER layout equalizer thread\n");
//         return -1;
//     }
    
//     init_waitqueue_head(&eq_finish_wq);

//     hk_info("Started HUNTER layout equalizer thread\n");
//     return 0;
    
// }

// int hk_terminal_equalizer(struct super_block *sb)
// {
//     struct hk_sb_info *sbi = HK_SB(sb);

//     if (sbi->layout_equalizer_thread) {
//         send_sig(SIGINT, sbi->layout_equalizer_thread, 1);
//         kthread_stop(sbi->layout_equalizer_thread);
//         sbi->layout_equalizer_thread = NULL;
//         hk_info("Terminated HUNTER layout equalizer thread\n");
//     }
    
//     return 0;
// }