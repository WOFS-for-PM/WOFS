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
    struct hk_sb_info     *sbi = HK_SB(sb);
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
    struct hk_sb_info     *sbi = HK_SB(sb);
    struct hk_mregion     *rg;
    int rgid;

    for (rgid = 0; rgid < sbi->rg_slots; rgid++) {
        rg = hk_get_region_by_rgid(sb, rgid);
        if (le64_to_cpu(rg->ino) != (u64)-1) {
            hk_applying_region(sb, rg);
        }
    }
    hk_info("regions dumped OK\n");

    return 0;
}

static int hk_inode_recovery_from_jentry(struct super_block *sb, struct hk_jentry *je)
{
    struct hk_inode  *pi;

#ifndef CONFIG_FINEGRAIN_JOURNAL
    pi = hk_get_inode_by_ino(sb, le64_to_cpu(je->jinode.ino));     
    pi->i_flags = je->jinode.i_flags;	      
    pi->i_size = je->jinode.i_size;		 	   
    pi->i_ctime = je->jinode.i_ctime;	 	  
    pi->i_mtime = je->jinode.i_mtime;	 	   
    pi->i_atime = je->jinode.i_atime;	 	  
    pi->i_mode = je->jinode.i_mode;		 	  
    pi->i_links_count = je->jinode.i_links_count;	  
    pi->i_xattr = je->jinode.i_xattr;	 	  
    pi->i_uid = je->jinode.i_uid;		 	  
    pi->i_gid = je->jinode.i_gid;		 	  
    pi->i_generation = je->jinode.i_generation;	   
    pi->i_create_time = je->jinode.i_create_time;	  
    pi->ino = je->jinode.ino;	 		  
    pi->h_addr = je->jinode.h_addr;	 	 	   
    pi->tstamp = je->jinode.tstamp;	 	
    pi->dev.rdev = je->jinode.dev.rdev;
#else
    //TODO: Fine-grain inode recovery
#endif
    return 0;
}

static int hk_inode_recovery(struct super_block *sb, struct hk_inode *pi, struct hk_jentry *je_pi, 
                             bool create, bool invalidate)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    unsigned long irq_flags = 0;

#ifndef CONFIG_FINEGRAIN_JOURNAL
    hk_memunlock_inode(sb, pi, &irq_flags);
    if (!invalidate) {
        hk_inode_recovery_from_jentry(sb, je_pi);
        if (create) {
            pi->tstamp = get_version(sbi);
            hk_flush_buffer(pi, sizeof(struct hk_inode), true);
            pi->valid = 1;
            /* FIXME: Change len to CACHELINE_SIZE */
            hk_flush_buffer(pi, sizeof(struct hk_inode), true);
        }
    }
    else {
        pi->valid = 0;
        hk_flush_buffer(pi, sizeof(struct hk_inode), true);
    }
    hk_memlock_inode(sb, pi, &irq_flags);
#else
    // TODO: Fine-grain inode recovery
#endif
    return 0;
}

static int hk_dentry_recovery(struct super_block *sb, u64 dir_ino, struct hk_jentry *je_pd, bool invalidate)
{
    struct inode      *dir;
    const char        *name;
    int               name_len;
    u64               ino;
    u16               link_change = 0;

#ifndef CONFIG_FINEGRAIN_JOURNAL
    name_len = je_pd->jdentry.name_len;
    name = je_pd->jdentry.name;

    if (!invalidate) {
        link_change = je_pd->jdentry.links_count;
        ino = le64_to_cpu(je_pd->jdentry.ino);
    }
    else {
        link_change = 0;
        ino = 0;
    }

    dir = hk_iget(sb, dir_ino);
    hk_append_dentry_innvm(sb, dir, name, name_len, ino, link_change, NULL);
    iput(dir);
#else
    // TODO: Fine-grain dentry recovery
#endif
    return 0;
}

/* Re-do Recovery (Redo Journal) */
static int hk_journal_recovery(struct super_block *sb, int txid, struct hk_journal *jnl)
{
    int ret = 0;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_jentry  *je_pi;
    struct hk_jentry  *je_pd;
    struct hk_jentry  *je_pd_new;
    struct hk_jentry  *je_pi_par;
    struct hk_jentry  *je_pi_new;
    struct hk_jentry  *je_pd_sym;   /* only for symlink */
    
    struct hk_inode   *pi;
    
    struct inode      *dir, *inode;
    const char        *symname;
    int               symlen;
    unsigned long     irq_flags = 0;
    u8                jtype = jnl->jhdr.jtype;

#ifndef CONFIG_FINEGRAIN_JOURNAL
    switch (jtype)
    {
    case IDLE:
        goto out;
    case CREATE:
    case MKDIR:
    case LINK:
    case SYMLINK:
        /* fall thru */
        je_pi = hk_get_jentry_by_slotid(sb, txid, 0);
        je_pd = hk_get_jentry_by_slotid(sb, txid, 1);
        je_pi_par = hk_get_jentry_by_slotid(sb, txid, 2);

        /* 1. fix inode */
        pi = hk_get_inode_by_ino(sb, le64_to_cpu(je_pi->jinode.ino));
        if (jtype != LINK) {
            hk_inode_recovery(sb, pi, je_pi, true, false);
        }

        /* 2. re-append dentry to directory */
        hk_dentry_recovery(sb, le64_to_cpu(je_pi_par->jinode.ino), je_pd, false);

        /* 3. if it is a symlink, then re-build the block sym link */
        if (jtype == SYMLINK) {
            je_pd_sym = hk_get_jentry_by_slotid(sb, txid, 3);
            symname = je_pd_sym->jdentry.name;
            symlen = je_pd_sym->jdentry.name_len;

            inode = hk_iget(sb, le64_to_cpu(pi->ino));
            hk_block_symlink(sb, pi, inode, symname, symlen, NULL);
            iput(inode);
        }

        break;
    case UNLINK:
        je_pi = hk_get_jentry_by_slotid(sb, txid, 0);
        je_pd = hk_get_jentry_by_slotid(sb, txid, 1);
        je_pi_par = hk_get_jentry_by_slotid(sb, txid, 2);

        /* 1. re-remove denrty from directory */
        hk_dentry_recovery(sb, le64_to_cpu(je_pi_par->jinode.ino), je_pd, true);
        
        /* 2. invalid inode */
        pi = hk_get_inode_by_ino(sb, le64_to_cpu(je_pi->jinode.ino));
        hk_inode_recovery(sb, pi, je_pi, false, true);
        
        /* 3. invalid blks belongs to inode, we don't need invalidators */
        hk_free_inode_blks_no_invalidators(sb, pi, NULL);

        break;
    case RENAME: 
        je_pi = hk_get_jentry_by_slotid(sb, txid, 0);       /* self */
        je_pd = hk_get_jentry_by_slotid(sb, txid, 1);       /* self-dentry */
        je_pd_new = hk_get_jentry_by_slotid(sb, txid, 2);   /* new-dentry */
        je_pi_par = hk_get_jentry_by_slotid(sb, txid, 3);   /* parent */
        je_pi_new = hk_get_jentry_by_slotid(sb, txid, 4);   /* new-parent */

        /* 1. fix inode */
        pi = hk_get_inode_by_ino(sb, le64_to_cpu(je_pi->jinode.ino));
        hk_inode_recovery(sb, pi, je_pi, false, false);
        
        /* 2. re-remove from parent */
        hk_dentry_recovery(sb, le64_to_cpu(je_pi_par->jinode.ino), je_pd, true);
        
        /* 3. re-add to new parent */
        hk_dentry_recovery(sb, le64_to_cpu(je_pi_new->jinode.ino), je_pd_new, false);

        break;   
    default:
        break;
    }
#else
    // TODO: Fine-grain journal recovery
#endif 

    hk_finish_tx(sb, txid);
out:
    return ret;
}

int hk_failure_recovery(struct super_block *sb)
{
    struct hk_sb_info     *sbi = HK_SB(sb);
    struct hk_super_block *hk_sb = sbi->hk_sb;
    struct hk_layout_info *layout; 
    struct hk_journal     *jnl;
    struct hk_mregion     *rg; 
    struct hk_header      *hdr;
    struct hk_inode       *pi; 
    u64                   not_free_blks = 0;
    u64                   blk = 0;
    u64                   addr = 0;   
    int                   cpuid, rgid, txid;
    unsigned long         irq_flags = 0;

    /* Revisiting Meta Regions Here */
    for (rgid = 0; rgid < sbi->rg_slots; rgid++) {
        rg = hk_get_region_by_rgid(sb, rgid);
        if (rg->applying || le64_to_cpu(rg->ino) != (u64)-1) {
            hk_applying_region(sb, rg);
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
        
        traverse_layout_blks(addr, layout) {
            hdr = sm_get_hdr_by_addr(sb, addr);
            if (hdr->valid) {
                pi = hk_get_inode_by_ino(sb, hdr->ino);
                /* Remove The Invalid Hdr */
                if (!pi->valid || hdr->tstamp > pi->tstamp) {
                    hk_memunlock_hdr(sb, hdr, &irq_flags);
                    hdr->valid = 0;
                    hk_memlock_hdr(sb, hdr, &irq_flags);

                    sm_remove_hdr(sb, pi, hdr);
                    ind_update(&layout->ind, PREP_LAYOUT_REMOVE, 1);
                }
                else {  /* Re insert */
                    sbi->tstamp = le64_to_cpu(pi->tstamp);
                    not_free_blks = blk + 1;

                    sm_remove_hdr(sb, pi, hdr);
                    sm_insert_hdr(sb, pi, hdr);
                    ind_update(&layout->ind, VALIDATE_BLK, 1);
                }
            }
            else {
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
    }
    else {
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
	} 
    else {
        hk_failure_recovery(sb);
    }

    HK_END_TIMING(recovery_t, start);

    return 0;
}
