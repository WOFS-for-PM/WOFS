/*
 * BRIEF DESCRIPTION
 *
 * Inode operations for directories.
 *
 * Copyright 2022-2023 Regents of the University of Harbin Institute of Technology, Shenzhen
 * Computer science and technology, Yanqi Pan <deadpoolmine@qq.com>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "hunter.h"

struct hk_dentry *hk_dentry_by_ix_from_blk(u64 blk_addr, u16 ix)
{
	return (struct hk_dentry *)(blk_addr + ix * sizeof(struct hk_dentry));
}

struct hk_dentry_info *hk_search_dir_table(struct super_block *sb, struct hk_inode_info_header *sih, const char *name, int namelen)
{
	struct hk_dentry_info *cur = NULL;
	unsigned long hash;
	
	hash = BKDRHash(name, namelen);
	
	hash_for_each_possible(sih->dirs, cur, node, hash) {
        if (strcmp(cur->direntry->name, name) == 0) {
            break;
        }
    }

	return cur;
}

int hk_insert_dir_table(struct super_block *sb, struct hk_inode_info_header *sih, const char *name, 
				  		int namelen, struct hk_dentry *direntry)
{
	struct hk_dentry_info 	*di;
	/* Insert into hash table */
	di = hk_alloc_dentry_info(sb);
	if (!di)
		return -ENOMEM;
	di->hash = BKDRHash(name, namelen);
	di->direntry = direntry;
	hk_dbgv("%s: insert %s hash %lu\n", __func__, name, di->hash);
	hash_add(sih->dirs, &di->node, di->hash);
}

int hk_update_dir_table(struct super_block *sb, struct hk_inode_info_header *sih, const char *name, 
				  		int namelen, struct hk_dentry *direntry)
{
	struct hk_dentry_info 	*di;
	di = hk_search_dir_table(sb, sih, name, namelen);
	if (!di)
		return -ENOENT;
	di->direntry = direntry;
	hk_dbgv("%s: update %s hash %lu\n", __func__, name, di->hash);
	return 0;
}

void hk_destory_dir_table(struct super_block *sb, struct hk_inode_info_header *sih)
{
	struct hk_dentry_info 	*di;
	struct hlist_node		*tmp;
	int 					bkt;
	
	hash_for_each_safe(sih->dirs, bkt, tmp, di, node) {
		hash_del(&di->node);
		hk_free_dentry_info(di);
	}
}

void hk_remove_dir_table(struct super_block *sb, struct hk_inode_info_header *sih, 
						 const char *name, int namelen)
{
	struct hk_dentry_info 	*di;
	struct hlist_node		*tmp;
	unsigned long 			hash;
	
	hash = BKDRHash(name, namelen);
	
	hash_for_each_possible_safe(sih->dirs, di, tmp, node, hash) {
		if (strcmp(di->direntry->name, name) == 0) {
			hash_del(&di->node);
			hk_free_dentry_info(di);
			break;
		}
	}
}

static ino_t hk_inode_by_name(struct inode *dir, struct qstr *entry,
				 			  struct hk_dentry **res_entry)
{
	struct super_block 	 		*sb = dir->i_sb;
	struct hk_sb_info  	 		*sbi = HK_SB(sb);
	struct hk_inode_info 		*si = HK_I(dir);
	struct hk_inode_info_header *sih = &si->header;
	struct hk_dentry_info 		*di;
	const char 	  *name;
	unsigned long name_len;

	name = entry->name;
	name_len = entry->len;
	// TODO: Only for the tets
	if (strcmp(name, "test") == 0)
	{
		return HK_NUM_INO - 1;	
	}

    di = hk_search_dir_table(sb, sih, name, name_len);
	if (!di) 
	{
		hk_dbgv("%s: %s not found\n", __func__, name);
		return -1;
	}

	*res_entry = di->direntry;

	return di->direntry->ino;
}

int hk_append_dentry_innvm(struct super_block *sb, struct inode *dir, const char *name, 
						   int namelen, u64 ino, u16 link_change, struct hk_dentry **out_direntry)
{
	struct hk_sb_info  	 	*sbi = HK_SB(sb);
	struct hk_inode_info 	*si = HK_I(dir);
	struct hk_inode_info_header *sih = &si->header;
	struct hk_inode 	 	*pidir;
	struct hk_layout_preps	preps;
	struct hk_layout_prep	*prep = NULL;
	struct hk_layout_prep	tmp_prep;
	struct hk_dentry_info   *di;
	struct hk_dentry 		*direntry;
	u64						blk_addr;
	u64						blk_cur;
	u16						dentry_ix;
	bool					is_alloc_new = false;
	unsigned long			irq_flags = 0;

	if (ino == 0) {
		di = hk_search_dir_table(sb, sih, name, namelen);
		if (!di) {
			return -ENOENT;		
		}
		
		direntry = di->direntry;
		direntry->tstamp = get_version(sbi);
		hk_memunlock_dentry(sb, direntry, &irq_flags);
		direntry->valid = 0;
		hk_memlock_dentry(sb, direntry, &irq_flags);
		hk_flush_buffer(direntry, sizeof(struct hk_dentry), true);
		
		if (out_direntry) {
			*out_direntry = direntry;
		}

		hk_remove_dir_table(sb, sih, name, namelen);
		return 0;
	}

	pidir = hk_get_inode(sb, dir);
	
	blk_cur = sih->i_num_dentrys / MAX_DENTRY_PER_BLK;
	dentry_ix = sih->i_num_dentrys % MAX_DENTRY_PER_BLK;
	if (dentry_ix == 0 && linix_get(&sih->ix, blk_cur) == 0) {
		hk_prepare_layouts(sb, 1, true, &preps);
		hk_trv_prepared_layouts_init(&preps);
		prep = hk_trv_prepared_layouts(sb, &preps);
		if (!prep) {
			hk_dbg("%s: ERROR: No prep found\n", __func__);
			hk_prepare_gap(sb, false, &tmp_prep);
			if (tmp_prep.target_addr == 0) {
				hk_dbgv("%s: prepare layout failed\n", __func__);
				BUG_ON(1);
				return -ENOSPC;	
			}
			blk_addr = tmp_prep.target_addr;
		}
		else {
			blk_addr = prep->target_addr;
		}
		is_alloc_new = true;
	}
	else {
		blk_addr = TRANS_OFS_TO_ADDR(sbi, linix_get(&sih->ix, blk_cur));
	}

	direntry = hk_dentry_by_ix_from_blk(blk_addr, dentry_ix);

	hk_memunlock_dentry(sb, direntry, &irq_flags);
	direntry->ino = cpu_to_le64(ino);
	direntry->name_len = namelen;
	memcpy_to_pmem_nocache(direntry->name, name, direntry->name_len);
	direntry->name[namelen] = '\0';
	direntry->mtime = cpu_to_le32(dir->i_mtime.tv_sec);
	direntry->links_count = cpu_to_le16(link_change);
	direntry->valid = 1;
	direntry->tstamp = get_version(sbi); 
	hk_memlock_dentry(sb, direntry, &irq_flags);

	if (out_direntry) {
		*out_direntry = direntry;
	}

	if (is_alloc_new) {
		use_layout_for_addr(sb, blk_addr);
		sm_valid_hdr(sb, blk_addr, dir->i_ino, blk_cur, get_version(sbi));
		unuse_layout_for_addr(sb, blk_addr);
		
		linix_insert(&sih->ix, blk_cur, blk_addr, true);
	}

	hk_flush_buffer(direntry, sizeof(struct hk_dentry), false);
	
	dir->i_mtime = dir->i_ctime = current_time(dir);
	sih->i_num_dentrys++;

	//TODO: Commit Out Side if CONFIG_FINEGRAIN_JOURNAL 
#ifndef CONFIG_FINEGRAIN_JOURNAL
	hk_commit_newattr_indram(sb, dir);
#endif

	hk_insert_dir_table(sb, sih, name, namelen, direntry);
	
	return 0;
}

/* adds a directory entry pointing to the inode.
 * return the directory in out_direntry field
 */
int hk_add_dentry(struct dentry *dentry, u64 ino, u16 link_change, 
				  struct hk_dentry **out_direntry)
{
	struct inode 	   	 	*dir = dentry->d_parent->d_inode;
	struct super_block 		*sb = dir->i_sb;
	const char 			 	*name = dentry->d_name.name;
	int 				 	namelen = dentry->d_name.len;
	int 				 	ret = 0;

	INIT_TIMING(add_dentry_time);

	hk_dbgv("%s: dir %lu new inode %llu\n",
			__func__, dir->i_ino, ino);
	hk_dbgv("%s: %s %d\n", __func__, name, namelen);
	HK_START_TIMING(add_dentry_t, add_dentry_time);
	
	if (namelen == 0)
		return -EINVAL;

	ret = hk_append_dentry_innvm(sb, dir, name, namelen, ino, link_change, out_direntry);
	
	HK_END_TIMING(add_dentry_t, add_dentry_time);
	return ret;
}

struct dentry *hk_get_parent(struct dentry *child)
{
	struct inode *inode;
	struct qstr dotdot = QSTR_INIT("..", 2);
	struct hk_dentry *de = NULL;
	ino_t ino;

	// FIXME: Change to this: 
	// child->d_parent->d_inode->i_ino;
	
	hk_inode_by_name(child->d_inode, &dotdot, &de);
	if (!de)
		return ERR_PTR(-ENOENT);

	/* FIXME: can de->ino be avoided by using the return value of
	 * hk_inode_by_name()?
	 */
	ino = le64_to_cpu(de->ino);

	if (ino)
		inode = hk_iget(child->d_inode->i_sb, ino);
	else
		return ERR_PTR(-ENOENT);

	return d_obtain_alias(inode);
}

static int hk_build_pseudo_dentry_for_tx(struct hk_dentry *direntry, u64 ino, struct dentry *dentry, 
										 struct inode *dir)
{
	struct hk_inode *pidir;

	pidir = hk_get_inode(dir->i_sb, dir);

	/* Construct Pseudo direntry  */
	direntry->ino = cpu_to_le64(ino);
	direntry->name_len = dentry->d_name.len;
	memcpy(direntry->name, dentry->d_name.name, direntry->name_len);
	direntry->name[dentry->d_name.len] = '\0';
	direntry->mtime = cpu_to_le32(dir->i_mtime.tv_sec);
	direntry->links_count = cpu_to_le16(0);
	direntry->valid = 1;
	direntry->tstamp = pidir->tstamp;

	return 0;
}

static int hk_build_pseudo_inode_for_tx(struct hk_inode *pi, struct super_block *sb, u64 ino,
									 	struct hk_inode *pidir, struct inode *dir, umode_t mode, dev_t rdev)
{
	struct hk_sb_info *sbi = HK_SB(sb);
	struct inode *inode;
	struct hk_inode_info_header *sih;
	int ret = 0;

	/* Construct Pseudo Inode */
	inode = new_inode(sb);
	if (!inode) {
		ret = -ENOMEM;
		goto out;
	}
	
	inode_init_owner(inode, dir, mode);
	inode->i_blocks = inode->i_size = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_generation = atomic_add_return(1, &sbi->next_generation);
	atomic_dec(&sbi->next_generation);
	inode->i_size = 0;
	inode->i_ino = ino;
	if (rdev) {
		init_special_inode(inode, mode, rdev);
	}
	
	/* for handle evict */
	sih = HK_IH(inode);
	hk_init_header(sb, sih, S_IFPSEUDO);
	
	pi->i_flags = hk_mask_flags(mode, pidir->i_flags);
	pi->ino = ino;
	pi->i_create_time = current_time(inode).tv_sec;
	hk_init_inode(inode, pi);

out:
	iput(inode);
	return ret;
}

#ifndef CONFIG_FINEGRAIN_JOURNAL
static int hk_start_tx_for_new_inode(struct super_block *sb, u64 ino, struct dentry *dentry, 
									 struct inode *dir, umode_t mode, dev_t rdev)
{
	struct hk_inode   *pidir = NULL;
	INIT_TIMING(trans_time);

	int ret = 0;

	HK_START_TIMING(create_trans_t, trans_time);
	pidir = hk_get_inode(sb, dir);
	if (!pidir) {
		ret = -ENOENT;
		goto out;
	} 

	struct hk_inode   pi;
	struct hk_dentry  direntry;
	ret = hk_build_pseudo_dentry_for_tx(&direntry, ino, dentry, dir);
	if (ret) {
		goto out;
	}
	
	ret = hk_build_pseudo_inode_for_tx(&pi, sb, ino, pidir, dir, mode, rdev);
	if (ret) {
		goto out;
	}

	switch (mode & S_IFMT) {
	case S_IFDIR:
		ret = hk_start_tx(sb, MKDIR, &pi, &direntry, pidir);
		break;
	case S_IFREG:
		ret = hk_start_tx(sb, CREATE, &pi, &direntry, pidir);
		break;
	case S_IFLNK:	/* hard link only */
		ret = hk_start_tx(sb, LINK, &pi, &direntry, pidir);
		break;
	default:
		ret = hk_start_tx(sb, CREATE, &pi, &direntry, pidir);
		break;
	}

out:
	HK_END_TIMING(create_trans_t, trans_time);
	return ret;
}
#else
static int hk_start_tx_for_new_inode(struct super_block *sb, u64 ino, struct hk_dentry *direntry, 
									 struct inode *dir, umode_t mode, dev_t rdev)
{
	struct hk_inode   *pidir = NULL;
	struct hk_inode   	   		*pi;
	struct hk_inode_info_header *sih = HK_IH(dir);
	unsigned long 	  irq_flags = 0;

	INIT_TIMING(trans_time);

	int ret = 0;
	HK_START_TIMING(create_trans_t, trans_time);
	pidir = hk_get_inode(sb, dir);
	if (!pidir) {
		ret = -ENOENT;
		goto out;
	} 

	pi = hk_get_inode_by_ino(sb, ino);

	switch (mode & S_IFMT) {
	case S_IFDIR:
		ret = hk_start_tx(sb, MKDIR, pi, direntry, pidir);
		break;
	case S_IFREG:
		ret = hk_start_tx(sb, CREATE, pi, direntry, pidir);
		break;
	case S_IFLNK:	/* hard link only */
		ret = hk_start_tx(sb, LINK, pi, direntry, pidir);
		break;
	default:
		ret = hk_start_tx(sb, CREATE, pi, direntry, pidir);
		break;
	}
	
	hk_memunlock_inode(sb, pi, &irq_flags);
	pi->valid = 1;
	hk_memlock_inode(sb, pi, &irq_flags);
	
out:
	HK_END_TIMING(create_trans_t, trans_time);
	return ret;
}
#endif

#ifndef CONFIG_FINEGRAIN_JOURNAL 
static int hk_start_tx_for_unlink(struct super_block *sb, struct hk_inode *pi, 
								  struct dentry *dentry, struct hk_inode *pidir)
{
	struct hk_dentry_info		*di = NULL;
	struct hk_dentry 			*direntry;
	struct inode 	   	 		*dir = dentry->d_parent->d_inode;
	struct hk_inode_info_header *sih = HK_IH(dir);
	const char 			 		*name = dentry->d_name.name;
	int 				 		namelen = dentry->d_name.len;
	int							ret;

	/* make sure meta consistency */
	hk_applying_region_to_inode(sb, pi);
	
	di = hk_search_dir_table(sb, sih, name, namelen);
	if (!di) {
		return -ENOENT;		
	}
	
	ret = hk_start_tx(sb, UNLINK, pi, direntry, pidir);
out:
	return ret;
}
#else
static int hk_start_tx_for_unlink(struct super_block *sb, struct hk_inode *pi, 
								  struct hk_dentry *direntry, struct hk_inode *pidir, 
								  bool invalidate)
{
	int ret = 0;
	unsigned long 	  irq_flags = 0;
	/* make sure meta consistency */
	hk_applying_region_to_inode(sb, pi);
	ret = hk_start_tx(sb, UNLINK, pi, direntry, pidir);

	if (invalidate) {
		hk_memunlock_inode(sb, pi, &irq_flags);
		pi->valid = 0;
		hk_memlock_inode(sb, pi, &irq_flags);
	}
out:
	return ret;
}
#endif

/* Returns new tail after append */
/*
 * By the time this is called, we already have created
 * the directory cache entry for the new file, but it
 * is so far negative - it has no inode.
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate().
 */
static int hk_create(struct inode *dir, struct dentry *dentry, umode_t mode,
			bool excl)
{
	struct inode *inode = NULL;
	int err = PTR_ERR(inode);
	struct super_block *sb = dir->i_sb;
	struct hk_inode *pidir, *pi;
	struct hk_dentry *direntry;
	u64 pi_addr = 0;
	u64 ino;
	int txid;
	INIT_TIMING(create_time);

	HK_START_TIMING(create_t, create_time);

	pidir = hk_get_inode(sb, dir);
	if (!pidir)
		goto out_err;

	ino = hk_get_new_ino(sb);
	if (ino == -1)
		goto out_err;

	// TODO: No entry now
	// update.tail = 0;
	// update.alter_tail = 0;
	// err = hk_add_dentry(dentry, ino, 0, &update, epoch_id);
	// if (err)
	// 	goto out_err;

#ifndef CONFIG_FINEGRAIN_JOURNAL
	txid = hk_start_tx_for_new_inode(sb, ino, dentry, dir, mode, 0);
	if (txid < 0) {
		err = txid;
		goto out_err;
	}
#endif

	err = hk_add_dentry(dentry, ino, 0, &direntry);
	if (err)
		goto out_err;
	
	hk_dbgv("%s: %s\n", __func__, dentry->d_name.name);
	hk_dbgv("%s: inode %llu, dir %lu\n", __func__, ino, dir->i_ino);
	
	inode = hk_create_inode(TYPE_CREATE, dir, ino, mode,
							0, 0, &dentry->d_name);
	if (IS_ERR(inode))
		goto out_err;

#ifdef CONFIG_FINEGRAIN_JOURNAL
	txid = hk_start_tx_for_new_inode(sb, ino, direntry, dir, mode, 0);
	if (txid < 0) {
		err = txid;
		goto out_err;
	}
	hk_commit_newattr_indram(sb, dir);
#endif

	hk_finish_tx(sb, txid);

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	HK_END_TIMING(create_t, create_time);
	return err;
	
out_err:
	hk_err(sb, "%s return %d\n", __func__, err);
	HK_END_TIMING(create_t, create_time);
	return err;
}

static struct dentry *hk_lookup(struct inode *dir, struct dentry *dentry,
				   unsigned int flags)
{
	struct inode *inode = NULL;
	struct hk_dentry *de;
	ino_t ino;
	INIT_TIMING(lookup_time);

	HK_START_TIMING(lookup_t, lookup_time);
	if (dentry->d_name.len > HK_NAME_LEN) {
		hk_dbg("%s: namelen %u exceeds limit\n",
			__func__, dentry->d_name.len);
		return ERR_PTR(-ENAMETOOLONG);
	}

	hk_dbgv("%s: %s\n", __func__, dentry->d_name.name);
	ino = hk_inode_by_name(dir, &dentry->d_name, &de);
	hk_dbgv("%s: ino %lu\n", __func__, ino);

	if (ino != -1) {
		inode = hk_iget(dir->i_sb, ino);
		if (inode == ERR_PTR(-ESTALE) || inode == ERR_PTR(-ENOMEM)
			|| inode == ERR_PTR(-EACCES)) {
			hk_err(dir->i_sb,
				  "%s: get inode failed: %lu\n",
				  __func__, (unsigned long)ino);
			return ERR_PTR(-EIO);
		}
	}

	HK_END_TIMING(lookup_t, lookup_time);
	return d_splice_alias(inode, dentry);
}

static int hk_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		       dev_t rdev)
{
	struct inode *inode = NULL;
	int err = PTR_ERR(inode);
	struct super_block *sb = dir->i_sb;
	u64 pi_addr = 0;
	struct hk_inode *pidir, *pi;
	struct hk_dentry *direntry;
	u64 ino;
	int txid;
	INIT_TIMING(mknod_time);

	HK_START_TIMING(mknod_t, mknod_time);

	pidir = hk_get_inode(sb, dir);
	if (!pidir)
		goto out_err;
			
	ino = hk_get_new_ino(sb);
	if (ino == -1)
		goto out_err;

#ifndef CONFIG_FINEGRAIN_JOURNAL
	txid = hk_start_tx_for_new_inode(sb, ino, dentry, dir, mode, rdev);
	if (txid < 0) {
		err = txid;
		goto out_err;
	}
#endif

	err = hk_add_dentry(dentry, ino, 0, &direntry);
	if (err)
		goto out_err;

	hk_dbgv("%s: %s\n", __func__, dentry->d_name.name);
	hk_dbgv("%s: inode %llu, dir %lu\n", __func__, ino, dir->i_ino);

	inode = hk_create_inode(TYPE_MKNOD, dir, ino, mode,
							0, rdev, &dentry->d_name);
	if (IS_ERR(inode))
		goto out_err;

#ifdef CONFIG_FINEGRAIN_JOURNAL
	txid = hk_start_tx_for_new_inode(sb, ino, direntry, dir, mode, rdev);
	if (txid < 0) {
		err = txid;
		goto out_err;
	}
	hk_commit_newattr_indram(sb, dir);
#endif

	hk_finish_tx(sb, txid);

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	HK_END_TIMING(mknod_t, mknod_time);
	return err;

out_err:
	hk_err(sb, "%s return %d\n", __func__, err);
	HK_END_TIMING(mknod_t, mknod_time);
	return err;
}

#ifndef CONFIG_FINEGRAIN_JOURNAL
static int hk_start_tx_for_symlink(struct super_block *sb, u64 ino, struct dentry *dentry, 
									 struct inode *dir, umode_t mode,  
									 const char *symname, int symlen)
#else
static int hk_start_tx_for_symlink(struct super_block *sb, u64 ino, struct hk_dentry *direntry, 
									 struct inode *dir, umode_t mode, u64 sym_blk_addr)
#endif
{
	struct hk_inode   *pidir = NULL;

	int ret = 0;
	
	pidir = hk_get_inode(sb, dir);
	if (!pidir) {
		ret = -ENOENT;
		goto out;
	} 

#ifndef CONFIG_FINEGRAIN_JOURNAL
	struct hk_inode   pi;
	struct hk_dentry  direntry;
	struct hk_dentry  symentry;

	/* create symentry */
	symentry.name_len = symlen;
	memcpy(symentry.name, symname, symlen);
	symentry.name[symlen] = '\0';

	ret = hk_build_pseudo_dentry_for_tx(&direntry, ino, dentry, dir);
	if (ret) {
		goto out;
	}
	
	ret = hk_build_pseudo_inode_for_tx(&pi, sb, ino, pidir, dir, mode, 0);
	if (ret) {
		goto out;
	}

	ret = hk_start_tx(sb, SYMLINK, &pi, &direntry, pidir, &symentry);
#else
	struct hk_inode   *pi;
	pi = hk_get_inode_by_ino(sb, ino);

	ret = hk_start_tx(sb, SYMLINK, pi, direntry, pidir, sym_blk_addr);
#endif
	
out:
	return ret;
}

static int hk_symlink(struct inode *dir, struct dentry *dentry,
			 const char *symname)
{
	struct super_block *sb = dir->i_sb;
	int err = -ENAMETOOLONG;
	unsigned int len = strlen(symname);
	struct inode *inode;
	struct hk_inode_info *si;
	struct hk_inode_info_header *sih;
	struct hk_inode  *pidir, *pi;
	struct hk_dentry *direntry;
	u64 sym_blk_addr = 0;
	u64 ino;
	int txid;

	INIT_TIMING(symlink_time);

	HK_START_TIMING(symlink_t, symlink_time);
	if (len + 1 > sb->s_blocksize)
		goto out;

	pidir = hk_get_inode(sb, dir);
	if (!pidir)
		goto out_fail;

	ino = hk_get_new_ino(sb);
	if (ino == 0)
		goto out_fail;

	hk_dbgv("%s: name %s, symname %s\n", __func__,
				dentry->d_name.name, symname);
	hk_dbgv("%s: inode %llu, dir %lu\n", __func__, ino, dir->i_ino);

#ifndef CONFIG_FINEGRAIN_JOURNAL
	txid = hk_start_tx_for_symlink(sb, ino, dentry, dir, S_IFLNK|0777, symname, len);
	if (txid < 0) {
		err = txid;
		goto out_fail;
	}
#endif

	err = hk_add_dentry(dentry, ino, 0, &direntry);
	if (err)
		goto out_fail;

	inode = hk_create_inode(TYPE_SYMLINK, dir, ino, S_IFLNK|0777,
							len, 0, &dentry->d_name);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_fail;
	}

	pi = hk_get_inode(sb, inode);

	si = HK_I(inode);
	sih = &si->header;

	err = hk_block_symlink(sb, pi, inode, symname, len, &sym_blk_addr);
	if (err)
		goto out_fail;

#ifdef CONFIG_FINEGRAIN_JOURNAL
	txid = hk_start_tx_for_symlink(sb, ino, direntry, dir, S_IFLNK|0777, sym_blk_addr);
	if (txid < 0) {
		err = txid;
		goto out_fail;
	}
	hk_commit_newattr_indram(sb, dir);
	hk_commit_sizechange(sb, inode, len);
#endif
	hk_finish_tx(sb, txid);

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);
	
out:
	HK_END_TIMING(symlink_t, symlink_time);
	return err;

out_fail:
	hk_err(sb, "%s return %d\n", __func__, err);
	goto out;
}

static int hk_link(struct dentry *dest_dentry, struct inode *dir,
		      struct dentry *dentry)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode = dest_dentry->d_inode;
	struct hk_inode *pi = hk_get_inode(sb, inode);
	struct hk_inode *pidir;
	struct hk_dentry *direntry;
	int err = -ENOMEM;
	int txid;
	INIT_TIMING(link_time);

	HK_START_TIMING(link_t, link_time);
	if (inode->i_nlink >= HK_LINK_MAX) {
		err = -EMLINK;
		goto out;
	}

	pidir = hk_get_inode(sb, dir);
	if (!pidir) {
		err = -EINVAL;
		goto out;
	}

	ihold(inode);

	hk_dbgv("%s: name %s, dest %s\n", __func__,
			dentry->d_name.name, dest_dentry->d_name.name);
	hk_dbgv("%s: inode %lu, dir %lu\n", __func__,
			inode->i_ino, dir->i_ino);

#ifndef CONFIG_FINEGRAIN_JOURNAL
	txid = hk_start_tx_for_new_inode(sb, inode->i_ino, dentry, dir, S_IFLNK|0777, 0);
	if (txid < 0) {
		err = txid;
		iput(inode);
		goto out;
	}
#endif 

	err = hk_add_dentry(dentry, inode->i_ino, 0, &direntry);
	if (err) {
		iput(inode);
		goto out;
	}

	inode->i_ctime = current_time(inode);
	inc_nlink(inode);

#ifdef CONFIG_FINEGRAIN_JOURNAL
	txid = hk_start_tx_for_new_inode(sb, inode->i_ino, direntry, dir, S_IFLNK|0777, 0);
	if (txid < 0) {
		err = txid;
		iput(inode);
		goto out;
	}
	hk_commit_newattr_indram(sb, dir);
#endif
	hk_commit_linkchange_indram(sb, inode);
	hk_finish_tx(sb, txid);

	d_instantiate(dentry, inode);

out:
	HK_END_TIMING(link_t, link_time);
	return err;
}


static int hk_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode 	 	*inode = dentry->d_inode;
	struct super_block 	*sb = dir->i_sb;
	int 			    retval = -ENOMEM;
	struct hk_inode 	*pi = hk_get_inode(sb, inode);
	struct hk_inode 	*pidir;
	struct hk_dentry 	*direntry;
	bool				invalidate = false;
	int					txid;

	INIT_TIMING(unlink_time);

	HK_START_TIMING(unlink_t, unlink_time);

	pidir = hk_get_inode(sb, dir);
	if (!pidir)
		goto out_err;

#ifndef CONFIG_FINEGRAIN_JOURNAL 
	txid = hk_start_tx_for_unlink(sb, pi, dentry, pidir);
	if (txid < 0) {
		retval = txid;
		goto out_err;
	}
#endif

	retval = hk_add_dentry(dentry, 0, 0, &direntry);
	if (retval)
		goto out_err;


	inode->i_ctime = dir->i_ctime;
	
	if (inode->i_nlink == 1)
		invalidate = true;

	if (inode->i_nlink)
		drop_nlink(inode);
	
#ifdef CONFIG_FINEGRAIN_JOURNAL
	txid = hk_start_tx_for_unlink(sb, pi, direntry, pidir, invalidate);
	if (txid < 0) {
		retval = txid;
		goto out_err;
	}
	hk_commit_newattr_indram(sb, dir);
#endif
	hk_commit_linkchange_indram(sb, inode);
	
	hk_finish_tx(sb, txid);

	HK_END_TIMING(unlink_t, unlink_time);
	return 0;

out_err:
	hk_err(sb, "%s return %d\n", __func__, retval);
	HK_END_TIMING(unlink_t, unlink_time);
	return retval;
}

static int hk_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode;
	struct super_block *sb = dir->i_sb;
	struct hk_inode *pidir, *pi;
	struct hk_dentry *direntry;
	struct hk_inode_info *si, *sidir;
	struct hk_inode_info_header *sih = NULL;

	u64 pi_addr = 0;
	u64 ino;
	int err = -EMLINK;
	int txid;
	INIT_TIMING(mkdir_time);

	HK_START_TIMING(mkdir_t, mkdir_time);
	if (dir->i_nlink >= HK_LINK_MAX)
		goto out;

	ino = hk_get_new_ino(sb);
	if (ino == 0)
		goto out_err;

	hk_dbgv("%s: name %s\n", __func__, dentry->d_name.name);
	hk_dbgv("%s: inode %llu, dir %lu, link %d\n", __func__,
				ino, dir->i_ino, dir->i_nlink);

#ifndef CONFIG_FINEGRAIN_JOURNAL
	txid = hk_start_tx_for_new_inode(sb, ino, dentry, dir, S_IFDIR | mode, 0);
	if (txid < 0) {
		err = txid;
		goto out_err;
	}
#endif

	err = hk_add_dentry(dentry, ino, 0, &direntry);
	if (err)
		goto out_err;

	inode = hk_create_inode(TYPE_MKDIR, dir, ino, S_IFDIR | mode, 
							0, 0, &dentry->d_name);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_err;
	}

	pi = hk_get_inode(sb, inode);
	si = HK_I(inode);
	
	// TODO: Append Dir Init Entries (ie, . and ..)
	// err = hk_append_dir_init_entries(sb, pi, inode->i_ino, dir->i_ino,
	// 				epoch_id);
	// if (err < 0)
	// 	goto out_err;
	pidir = hk_get_inode(sb, dir);
	sidir = HK_I(dir);

	sih = &si->header;

	// TODO: What's this
	dir->i_blocks = sih->i_blocks;

	inc_nlink(dir);

#ifdef CONFIG_FINEGRAIN_JOURNAL
	txid = hk_start_tx_for_new_inode(sb, ino, direntry, dir, S_IFDIR | mode, 0);
	if (txid < 0) {
		err = txid;
		goto out_err;
	}
	hk_commit_newattr_indram(sb, dir);
#endif
	hk_finish_tx(sb, txid);

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

out:
	HK_END_TIMING(mkdir_t, mkdir_time);
	return err;

out_err:
//	clear_nlink(inode);
	hk_err(sb, "%s return %d\n", __func__, err);
	goto out;
}

/*
 * routine to check that the specified directory is empty (for rmdir)
 */
static bool hk_empty_dir(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct hk_inode_info *si = HK_I(inode);
	struct hk_inode_info_header *sih = &si->header;
	unsigned bkt;
	struct hk_dentry_info *cur;

	hash_for_each(sih->dirs, bkt, cur, node) {
		return false;
    }

	return true;
}

#ifndef CONFIG_FINEGRAIN_JOURNAL
static int hk_start_tx_for_rename(struct super_block *sb, struct hk_inode *pi, 
								  struct inode *old_dir, struct dentry *old_dentry, 
								  struct inode *new_dir, struct dentry *new_dentry, 
								  struct hk_inode *pi_par, struct hk_inode *pi_new)
{
	struct hk_dentry pd;
	struct hk_dentry pd_new;
	int    ret;
	u64    ino = le64_to_cpu(pi->ino);

	/* make sure meta consistency */
	hk_applying_region_to_inode(sb, pi);

	ret = hk_build_pseudo_dentry_for_tx(&pd, ino, old_dentry, old_dir);
	if (ret) {
		goto out;
	}

	ret = hk_build_pseudo_dentry_for_tx(&pd_new, ino, new_dentry, new_dir);
	if (ret) {
		goto out;
	}

	ret = hk_start_tx(sb, RENAME, pi, &pd, &pd_new, pi_par, pi_new);
out:
	return ret;
}
#else
static int hk_start_tx_for_rename(struct super_block *sb, struct hk_inode *pi, 
								  struct hk_dentry *pd, struct hk_dentry *pd_new, 
								  struct hk_inode *pi_par, struct hk_inode *pi_new)
{
	int    ret;
	u64    ino = le64_to_cpu(pi->ino);

	/* make sure meta consistency */
	hk_applying_region_to_inode(sb, pi);

	ret = hk_start_tx(sb, RENAME, pi, pd, pd_new, pi_par, pi_new);
out:
	return ret;
}
#endif

static int hk_rename(struct inode *old_dir,
			struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry,
			unsigned int flags)
{
	struct inode *old_inode = old_dentry->d_inode;
	struct inode *new_inode = new_dentry->d_inode;
	struct super_block *sb = old_inode->i_sb;
	struct hk_sb_info *sbi = HK_SB(sb);
	struct hk_inode *old_pi = NULL, *new_pi = NULL;
	struct hk_inode *new_pidir = NULL, *old_pidir = NULL;
	struct hk_dentry *father_entry = NULL;
	struct hk_dentry *father_entryc, entry_copy;
	struct hk_dentry *pd, *pd_new;
	int invalidate_new_inode = 0;
	int err = 0;
	int inc_link = 0, dec_link = 0;
	unsigned long irq_flags = 0;
	int txid;

	INIT_TIMING(rename_time);

	hk_dbgv("%s: rename %s to %s,\n", __func__,
			old_dentry->d_name.name, new_dentry->d_name.name);
	hk_dbgv("%s: %s inode %lu, old dir %lu, new dir %lu, new inode %lu\n",
			__func__, S_ISDIR(old_inode->i_mode) ? "dir" : "normal",
			old_inode->i_ino, old_dir->i_ino, new_dir->i_ino,
			new_inode ? new_inode->i_ino : 0);

	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	HK_START_TIMING(rename_t, rename_time);

	if (new_inode) {
		err = -ENOTEMPTY;
		if (S_ISDIR(old_inode->i_mode) && !hk_empty_dir(new_inode))
			goto out;
	} else {
		if (S_ISDIR(old_inode->i_mode)) {
			err = -EMLINK;
			if (new_dir->i_nlink >= HK_LINK_MAX)
				goto out;
		}
	}

	if (S_ISDIR(old_inode->i_mode)) {
		dec_link = -1;
		if (!new_inode)
			inc_link = 1;
		/*
		 * Tricky for in-place update:
		 * New dentry is always after renamed dentry, so we have to
		 * make sure new dentry has the correct links count
		 * to workaround the rebuild nlink issue.
		 */
		if (old_dir == new_dir) {
			inc_link--;
			if (inc_link == 0)
				dec_link = 0;
		}
	}

	new_pidir = hk_get_inode(sb, new_dir);
	old_pidir = hk_get_inode(sb, old_dir);

	old_pi = hk_get_inode(sb, old_inode);

#ifndef CONFIG_FINEGRAIN_JOURNAL
	txid = hk_start_tx_for_rename(sb, old_pi, old_dir, old_dentry, 
						   	      new_dir, new_dentry, old_pidir, new_pidir);
	if (txid < 0) {
		err = txid;
		goto out;
	}
#endif

	old_inode->i_ctime = current_time(old_inode);
	err = hk_commit_linkchange_indram(sb, old_inode);
	if (err)
		goto out;

	/* FIXME we don't support ".." for now */

	if (new_inode) {
		/* First remove the old entry in the new directory */
		err = hk_add_dentry(new_dentry, 0, 0, NULL);
		if (err)
			goto out;
	}

	/* link into the new directory. */
	err = hk_add_dentry(new_dentry, old_inode->i_ino, inc_link, &pd_new);
	if (err)
		goto out;

	if (inc_link > 0)
		inc_nlink(new_dir);

	/* remove the old dentry */
	err = hk_add_dentry(old_dentry, 0, dec_link, &pd);
	if (err)
		goto out;

	if (dec_link < 0)
		drop_nlink(old_dir);

	if (new_inode) {
		new_pi = hk_get_inode(sb, new_inode);
		new_inode->i_ctime = current_time(new_inode);

		if (S_ISDIR(old_inode->i_mode)) {
			if (new_inode->i_nlink)
				drop_nlink(new_inode);
		}
		if (new_inode->i_nlink)
			drop_nlink(new_inode);

		err = hk_commit_linkchange_indram(sb, new_inode);
		if (err)
			goto out;
	}
	
	if (new_inode && new_inode->i_nlink == 0)
		invalidate_new_inode = 1;
	
	if (new_inode && invalidate_new_inode) {
		hk_memunlock_inode(sb, new_pi, &irq_flags);
		new_pi->valid = 0;
		hk_flush_buffer((void *)new_pi, sizeof(struct hk_inode), true);
		hk_memlock_inode(sb, new_pi, &irq_flags);
		hk_free_inode_blks(sb, new_pi, HK_IH(new_inode));
	}

#ifdef CONFIG_FINEGRAIN_JOURNAL
	txid = hk_start_tx_for_rename(sb, old_pi, pd, pd_new, 
								  old_pidir, new_pidir);
	if (txid < 0) {
		err = txid;
		goto out;
	}
	hk_commit_newattr_indram(sb, old_dir);
	hk_commit_newattr_indram(sb, new_dir);
#endif
	hk_finish_tx(sb, txid);

	HK_END_TIMING(rename_t, rename_time);
	return 0;

out:
	hk_err(sb, "%s return %d\n", __func__, err);
	HK_END_TIMING(rename_t, rename_time);
	return err;
}

const struct inode_operations hk_dir_inode_operations = {
	.create		= hk_create,
	.lookup		= hk_lookup,
	.link		= hk_link,
	.unlink		= hk_unlink,
	.symlink	= hk_symlink,
	.mkdir		= hk_mkdir,
	.rmdir		= NULL,
	.mknod		= hk_mknod,
	.rename		= hk_rename,
	.setattr	= hk_notify_change,
	.get_acl	= NULL,
};

const struct inode_operations hk_special_inode_operations = {
	.setattr	= hk_notify_change,
	.get_acl	= NULL,
};
