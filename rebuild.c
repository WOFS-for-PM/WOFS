/*
 * BRIEF DESCRIPTION
 *
 * HUNTER Inode rebuild methods.
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
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "hunter.h"

static void hk_update_inode_with_rebuild(struct super_block *sb, 
										 struct hk_inode_rebuild *reb, 
										 struct hk_inode *pi)
{
	pi->i_size = cpu_to_le64(reb->i_size);
	pi->i_flags = cpu_to_le32(reb->i_flags);
	pi->i_uid = cpu_to_le32(reb->i_uid);
	pi->i_gid = cpu_to_le32(reb->i_gid);
	pi->i_atime = cpu_to_le32(reb->i_atime);
	pi->i_ctime = cpu_to_le32(reb->i_ctime);
	pi->i_mtime = cpu_to_le32(reb->i_mtime);
	pi->i_generation = cpu_to_le32(reb->i_generation);
	pi->i_links_count = cpu_to_le16(reb->i_links_count);
	pi->i_mode = cpu_to_le16(reb->i_mode);
}

static int hk_init_inode_rebuild(struct super_block *sb, struct hk_inode_rebuild *reb, 
								 struct hk_inode *pi)
{
	reb->i_num_entrys = 0;
	reb->i_size = le64_to_cpu(pi->i_size);
	reb->i_flags = le32_to_cpu(pi->i_flags);
	reb->i_uid = le32_to_cpu(pi->i_uid);
	reb->i_gid = le32_to_cpu(pi->i_gid);
	reb->i_atime = le32_to_cpu(pi->i_atime);
	reb->i_ctime = le32_to_cpu(pi->i_ctime);
	reb->i_mtime = le32_to_cpu(pi->i_mtime);
	reb->i_generation = le32_to_cpu(pi->i_generation);
	reb->i_links_count = le16_to_cpu(pi->i_links_count);
	reb->i_mode = le16_to_cpu(pi->i_mode);
	reb->tstamp = le64_to_cpu(pi->tstamp);
	return 0;
}

static int hk_guess_slots(struct super_block *sb)
{
	struct hk_sb_info *sbi = HK_SB(sb);
	size_t avg_size;
	int    slots;

	avg_size = hk_dw_stat_avg(&sbi->dw);
	slots = avg_size / HK_LBLK_SZ(sbi) == 0 ? 1 : avg_size / HK_LBLK_SZ(sbi);
	return slots;
}

void hk_init_header(struct super_block *sb, struct hk_inode_info_header *sih, 
                    u16 i_mode)
{
	int slots = HK_LINIX_SLOTS;

	sih->i_size = 0;
	sih->ino = 0;
	sih->i_blocks = 0;
	sih->pi_addr = 0;

	if (S_ISPSEUDO(i_mode)) {
		linix_init(&sih->ix, 0);
	}
	else if (!S_ISLNK(i_mode)) {
		if (ENABLE_HISTORY_W(sb)) {
    		slots = hk_guess_slots(sb);
		}
		linix_init(&sih->ix, slots);
	}
	else {	/* symlink only need one block */
		linix_init(&sih->ix, 1);
	}

	hash_init(sih->dirs);
	sih->i_num_dentrys = 0;

	sih->vma_tree = RB_ROOT;
	sih->num_vmas = 0;
	INIT_LIST_HEAD(&sih->list);
	
    sih->i_mode = i_mode;
	sih->i_flags = 0;
	sih->last_setattr = 0;
	sih->last_link_change = 0;
	sih->last_dentry = 0;

	sih->tstamp = 0;
	sih->h_addr = 0;
	
    return 0;
}

static int hk_rebuild_blks_start(struct super_block *sb,
								 struct hk_inode *pi, struct hk_inode_info_header *sih,
								 struct hk_inode_rebuild *reb, u64 pi_addr)
{
	int ret;

	sih->h_addr = le64_to_cpu(pi->h_addr);

	ret = hk_init_inode_rebuild(sb, reb, pi);
	if (ret)
		return ret;

	sih->pi_addr = pi_addr;

	hk_dbg_verbose("Blk Summary head 0x%llx\n",
				    sih->h_addr);
	
	return ret;
}

static int hk_rebuild_blks_finish(struct super_block *sb, struct hk_inode *pi, 
								  struct hk_inode_info_header *sih,
								  struct hk_inode_rebuild *reb)
{
	unsigned long irq_flags = 0;

	sih->i_size = le64_to_cpu(reb->i_size);
	sih->i_mode = le64_to_cpu(reb->i_mode);
	sih->i_flags = le32_to_cpu(reb->i_flags);
	sih->i_num_dentrys = le64_to_cpu(reb->i_num_entrys); 
	sih->tstamp = reb->tstamp;

	hk_memunlock_inode(sb, pi, &irq_flags);
	hk_update_inode_with_rebuild(sb, reb, pi);
	hk_memlock_inode(sb, pi, &irq_flags);
	
	hk_flush_buffer(pi, sizeof(struct hk_inode), true);
	return 0;
}

static int hk_rebuild_dir_table_for_blk(struct super_block *sb, u64 f_blk, struct hk_inode_info_header *sih, 
										struct hk_inode_rebuild *reb)
{
	struct hk_sb_info *sbi = HK_SB(sb);
	struct hk_dentry  *direntry;
	u16 			 i;
	u64			 	 blk_addr;		
	for (i = 0; i < MAX_DENTRY_PER_BLK; i++)
	{
		blk_addr = TRANS_OFS_TO_ADDR(sbi, linix_get(&sih->ix, f_blk));
		direntry = hk_dentry_by_ix_from_blk(blk_addr, i);
		if (direntry->valid) 
		{
			reb->i_num_entrys += 1; 
			hk_insert_dir_table(sb, sih, direntry->name, direntry->name_len, direntry);
		}
	}
}

static int hk_rebuild_inode_blks(struct super_block *sb, struct hk_inode *pi,
	                            struct hk_inode_info_header *sih) 
{
    struct hk_sb_info *sbi = HK_SB(sb);
	struct hk_inode_rebuild rebuild, *reb;
	u64 					ino = pi->ino;
	u64 					addr;
	struct hk_header		*hdr;
	struct hk_header		*conflict_hdr;

	INIT_TIMING(rebuild_time);
	int ret;

	HK_START_TIMING(rebuild_blks_t, rebuild_time);
	hk_dbg_verbose("Rebuild file inode %llu tree\n", ino);
	
	reb = &rebuild;
	ret = hk_rebuild_blks_start(sb, pi, sih, reb, (u64)pi);
	if (ret)
		goto out;

	traverse_inode_hdr(sbi, pi, hdr)
	{
		/* Hdr Conflict */
		if (hdr->f_blk < sih->ix.num_slots && linix_get(&sih->ix, hdr->f_blk) != 0) {
			conflict_hdr = sm_get_hdr_by_addr(sb, TRANS_OFS_TO_ADDR(sbi, linix_get(&sih->ix, hdr->f_blk)));
			if (hdr->tstamp >= conflict_hdr->tstamp) {	/* Insert New, Evict Old */
				addr = sm_get_addr_by_hdr(sb, conflict_hdr);
				
				use_layout_for_addr(sb, addr);
                sm_invalid_hdr(sb, addr, conflict_hdr->ino);
				unuse_layout_for_addr(sb, addr);
                
				linix_insert(&sih->ix, hdr->f_blk, sm_get_addr_by_hdr(sb, hdr), true);
			}
			else {	/* Not Insert */
				addr = sm_get_addr_by_hdr(sb, hdr);

				use_layout_for_addr(sb, addr);
				sm_invalid_hdr(sb, addr, hdr->ino);
				unuse_layout_for_addr(sb, addr);
			}
		}
		else {
			linix_insert(&sih->ix, hdr->f_blk, sm_get_addr_by_hdr(sb, hdr), true);
		}
		
		switch (__le16_to_cpu(pi->i_mode) & S_IFMT) {
		case S_IFLNK:
		case S_IFREG:
			break;
		case S_IFDIR:
			hk_rebuild_dir_table_for_blk(sb, hdr->f_blk, sih, reb);
			break;
		default:
			break;
		}
	}

	ret = hk_rebuild_blks_finish(sb, pi, sih, reb);
	sih->i_blocks = sih->i_size / HK_LBLK_SZ(sbi);

out:
	HK_END_TIMING(rebuild_blks_t, rebuild_time);
	return ret;
}

int hk_check_inode(struct super_block *sb, u64 ino) {
	int ret;
	struct hk_inode *pi;
	
    // TODO: Check Inode Integrity
	pi = hk_get_inode_by_ino(sb, ino);
	ret = pi->valid == 1 ? 0 : -ESTALE;
	
	return ret;
}

/* initialize hunter inode header and other DRAM data structures */
int hk_rebuild_inode(struct super_block *sb, struct hk_inode_info *si, u64 ino, bool build_blks)
{
	struct hk_inode_info_header *sih = &si->header;
	struct hk_inode             *pi;
	unsigned long				irq_flags = 0;
	int ret;

	ret = hk_check_inode(sb, ino);
	if (ret) {
		pi = hk_get_inode_by_ino(sb, ino);
		hk_dump_inode(sb, pi);
		hk_warn("%s: Invalid inode: %llu, %d\n", __func__, ino, ret);
		return ret;
	}

	pi = (struct hk_inode *)hk_get_inode_by_ino(sb, ino);
	
	if (ENABLE_META_ASYNC(sb)) {
        hk_flush_cmt_inode_fast(sb, ino);
    }

	hk_applying_region_to_inode(sb, pi);

	// We need this valid in case we need to evict the inode.
	hk_init_header(sb, sih, le16_to_cpu(pi->i_mode));
	sih->pi_addr = (u64)pi;
	
	if (pi->valid == 0) {
		hk_dbg("%s: inode %llu is invalid or deleted.\n", __func__, ino);
		return -ESTALE;
	}

	hk_dbgv("%s: inode %llu, addr 0x%llx, valid %d, head 0x%llx\n",
			__func__, ino, sih->pi_addr, pi->valid, pi->h_addr);

	sih->ino = ino;
	
	if (build_blks)
		ret = hk_rebuild_inode_blks(sb, pi, sih);

	return ret;
}
