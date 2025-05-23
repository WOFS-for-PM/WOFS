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

void *hk_search_dir_table(struct super_block *sb, struct hk_inode_info_header *sih, const char *name, int namelen)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    void *cur = NULL;
    unsigned long hash;

    hash = BKDRHash(name, namelen);

    if (ENABLE_META_PACK(sb)) {
        obj_ref_dentry_t *ref_dentry = NULL;
        struct hk_obj_dentry *dentry;
        hash_for_each_possible(sih->dirs, ref_dentry, hnode, hash)
        {
            if (ref_dentry->hash != hash)
                continue;
            dentry = get_pm_addr(sbi, ref_dentry->hdr.addr);
            if (strcmp(dentry->name, name) == 0) {
                cur = ref_dentry;
                break;
            }
        }
    } else {
        struct hk_dentry_info *cur_di = NULL;
        hash_for_each_possible(sih->dirs, cur_di, node, hash)
        {
            if (cur_di->hash != hash)
                continue;
            if (strcmp(cur_di->direntry->name, name) == 0) {
                cur = cur_di;
                break;
            }
        }
    }

    return cur;
}

int hk_insert_dir_table(struct super_block *sb, struct hk_inode_info_header *sih, const char *name,
                        int namelen, void *direntry)
{
    if (ENABLE_META_PACK(sb)) {
        obj_ref_dentry_t *ref_dentry = direntry;
        hk_dbgv("%s: insert %s hash %lu\n", __func__, name, ref_dentry->hash);
        hash_add(sih->dirs, &ref_dentry->hnode, ref_dentry->hash);
    } else {
        struct hk_dentry_info *di;
        /* Insert into hash table */
        di = hk_alloc_hk_dentry_info();
        if (!di)
            return -ENOMEM;
        di->hash = BKDRHash(name, namelen);
        di->direntry = direntry;
        hk_dbgv("%s: insert %s hash %lu\n", __func__, name, di->hash);
        hash_add(sih->dirs, &di->node, di->hash);
    }
    return 0;
}

void hk_destory_dir_table(struct super_block *sb, struct hk_inode_info_header *sih)
{
    struct hlist_node *tmp;
    int bkt;

    if (ENABLE_META_PACK(sb)) {
        obj_ref_dentry_t *ref_dentry;
        hash_for_each_safe(sih->dirs, bkt, tmp, ref_dentry, hnode)
        {
            hash_del(&ref_dentry->hnode);
        }
    } else {
        struct hk_dentry_info *di;
        hash_for_each_safe(sih->dirs, bkt, tmp, di, node)
        {
            hash_del(&di->node);
            hk_free_hk_dentry_info(di);
        }
    }
}

/* if *ret_entry is not null, the caller hold the obj */
int hk_remove_dir_table(struct super_block *sb, struct hk_inode_info_header *sih,
                        const char *name, int namelen, void **ret_entry)
{
    struct hlist_node *tmp;
    unsigned long hash;
    int is_find = 0;
    int searches = 0;
    INIT_TIMING(time);

    hash = BKDRHash(name, namelen);

    if (ENABLE_META_PACK(sb)) {
        struct hk_sb_info *sbi = HK_SB(sb);
        obj_ref_dentry_t *ref_dentry;
        struct hk_obj_dentry *dentry;

        hash_for_each_possible_safe(sih->dirs, ref_dentry, tmp, hnode, hash)
        {
            searches++;
            if (ref_dentry->hash != hash)
                continue;
            dentry = get_pm_addr(sbi, ref_dentry->hdr.addr);
            if (strcmp(dentry->name, name) == 0) {
                hash_del(&ref_dentry->hnode);
                if (ret_entry)
                    *ret_entry = ref_dentry;
                else
                    ref_dentry_destroy(ref_dentry);
                is_find = 1;
                break;
            }
        }
    } else {
        struct hk_dentry_info *di;

        hash_for_each_possible_safe(sih->dirs, di, tmp, node, hash)
        {
            if (di->hash != hash)
                continue;
            if (strcmp(di->direntry->name, name) == 0) {
                hash_del(&di->node);
                if (ret_entry)
                    *ret_entry = di;
                else
                    hk_free_hk_dentry_info(di);
                is_find = 1;
                break;
            }
        }
    }
    if (searches > 500) {
        hk_warn("%s: Too many entry under the same entries %d\n", __func__, searches);
    }
    return is_find ? 0 : -ENOENT;
}

static ino_t hk_inode_by_name(struct inode *dir, struct qstr *entry,
                              void **ret_entry)
{
    struct super_block *sb = dir->i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info *si = HK_I(dir);
    struct hk_inode_info_header *sih = si->header;
    ino_t ino;
    const char *name;
    unsigned long name_len;

    name = entry->name;
    name_len = entry->len;

    if (ENABLE_META_PACK(sb)) {
        obj_ref_dentry_t *ref_dentry;
        ref_dentry = hk_search_dir_table(sb, sih, name, name_len);
        if (!ref_dentry) {
            hk_dbgv("%s: %s not found\n", __func__, name);
            return -1;
        }

        ino = ref_dentry->target_ino;
        if (ret_entry)
            *ret_entry = ref_dentry;
    } else {
        struct hk_dentry_info *di;
        di = hk_search_dir_table(sb, sih, name, name_len);
        if (!di) {
            hk_dbgv("%s: %s not found\n", __func__, name);
            return -1;
        }

        ino = di->direntry->ino;
        if (ret_entry)
            *ret_entry = di->direntry;
    }

    return ino;
}

int hk_append_dentry_innvm(struct super_block *sb, struct inode *dir, const char *name,
                           int namelen, u64 ino, u16 link_change, struct hk_dentry **out_direntry)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info *si = HK_I(dir);
    struct hk_inode_info_header *sih = si->header;
    struct hk_inode *pidir;
    struct hk_layout_prep prep;
    struct hk_dentry_info *di;
    struct hk_dentry *direntry;
    u64 blk_addr;
    u64 blk_cur;
    u16 dentry_ix;
    bool is_alloc_new = false;
    unsigned long irq_flags = 0;
    unsigned long blks;
    int ret = 0;

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

        hk_remove_dir_table(sb, sih, name, namelen, NULL);
        return 0;
    }

    pidir = hk_get_inode(sb, dir);

    blk_cur = sih->i_num_dentrys / MAX_DENTRY_PER_BLK;
    dentry_ix = sih->i_num_dentrys % MAX_DENTRY_PER_BLK;
    if (dentry_ix == 0 && linix_get(&sih->ix, blk_cur) == 0) {
        blks = 1;
        ret = hk_alloc_blocks(sb, &blks, true, &prep);
        if (ret) {
            hk_dbgv("%s: alloc blocks failed\n", __func__);
            ret = -ENOSPC;
            return ret;
        }
        blk_addr = prep.target_addr;
        is_alloc_new = true;
    } else {
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

        linix_insert(&sih->ix, blk_cur, TRANS_ADDR_TO_OFS(sbi, blk_addr), true);
    }

    hk_flush_buffer(direntry, sizeof(struct hk_dentry), false);

    dir->i_mtime = dir->i_ctime = current_time(dir);
    sih->i_num_dentrys++;

    // TODO: Commit Out Side if CONFIG_FINEGRAIN_JOURNAL
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
    struct inode *dir = dentry->d_parent->d_inode;
    struct super_block *sb = dir->i_sb;
    const char *name = dentry->d_name.name;
    int namelen = dentry->d_name.len;
    int ret = 0;

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
    ino_t ino;

    ino = child->d_parent->d_inode->i_ino;

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
    struct hk_inode *pidir = NULL;
    INIT_TIMING(trans_time);

    int ret = 0;

    HK_START_TIMING(new_inode_trans_t, trans_time);
    pidir = hk_get_inode(sb, dir);
    if (!pidir) {
        ret = -ENOENT;
        goto out;
    }

    struct hk_inode pi;
    struct hk_dentry direntry;
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
    case S_IFLNK: /* hard link only */
        ret = hk_start_tx(sb, LINK, &pi, &direntry, pidir);
        break;
    default:
        ret = hk_start_tx(sb, CREATE, &pi, &direntry, pidir);
        break;
    }

out:
    HK_END_TIMING(new_inode_trans_t, trans_time);
    return ret;
}
#else
static int hk_start_tx_for_new_inode(struct super_block *sb, u64 ino, struct hk_dentry *direntry,
                                     struct inode *dir, umode_t mode, dev_t rdev)
{
    struct hk_inode *pidir = NULL;
    struct hk_inode *pi;
    struct hk_inode_info_header *sih = HK_IH(dir);
    unsigned long irq_flags = 0;

    INIT_TIMING(trans_time);

    int ret = 0;
    HK_START_TIMING(new_inode_trans_t, trans_time);
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
    case S_IFLNK: /* hard link only */
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
    HK_END_TIMING(new_inode_trans_t, trans_time);
    return ret;
}
#endif

#ifndef CONFIG_FINEGRAIN_JOURNAL
static int hk_start_tx_for_unlink(struct super_block *sb, struct hk_inode *pi,
                                  struct dentry *dentry, struct hk_inode *pidir)
{
    struct hk_dentry_info *di = NULL;
    struct hk_dentry *direntry;
    struct inode *dir = dentry->d_parent->d_inode;
    struct hk_inode_info_header *sih = HK_IH(dir);
    const char *name = dentry->d_name.name;
    int namelen = dentry->d_name.len;
    int ret;

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
    unsigned long irq_flags = 0;
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

#ifndef CONFIG_FINEGRAIN_JOURNAL
static int hk_start_tx_for_symlink(struct super_block *sb, u64 ino, struct dentry *dentry,
                                   struct inode *dir, umode_t mode,
                                   const char *symname, int symlen)
#else
static int hk_start_tx_for_symlink(struct super_block *sb, u64 ino, struct hk_dentry *direntry,
                                   struct inode *dir, umode_t mode, u64 sym_blk_addr)
#endif
{
    struct hk_inode *pidir = NULL;

    int ret = 0;

    pidir = hk_get_inode(sb, dir);
    if (!pidir) {
        ret = -ENOENT;
        goto out;
    }

#ifndef CONFIG_FINEGRAIN_JOURNAL
    struct hk_inode pi;
    struct hk_dentry direntry;
    struct hk_dentry symentry;

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
    struct hk_inode *pi;
    pi = hk_get_inode_by_ino(sb, ino);

    ret = hk_start_tx(sb, SYMLINK, pi, direntry, pidir, sym_blk_addr);
#endif

out:
    return ret;
}

#ifndef CONFIG_FINEGRAIN_JOURNAL
static int hk_start_tx_for_rename(struct super_block *sb, struct hk_inode *pi,
                                  struct inode *old_dir, struct dentry *old_dentry,
                                  struct inode *new_dir, struct dentry *new_dentry,
                                  struct hk_inode *pi_par, struct hk_inode *pi_new)
{
    struct hk_dentry pd;
    struct hk_dentry pd_new;
    int ret;
    u64 ino = le64_to_cpu(pi->ino);

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
    int ret;
    u64 ino = le64_to_cpu(pi->ino);

    /* make sure meta consistency */
    hk_applying_region_to_inode(sb, pi);

    ret = hk_start_tx(sb, RENAME, pi, pd, pd_new, pi_par, pi_new);
out:
    return ret;
}
#endif

static struct dentry *hk_lookup(struct inode *dir, struct dentry *dentry,
                                unsigned int flags)
{
    struct inode *inode = NULL;
    void *ref;
    ino_t ino;
    struct hk_inode_info_header *sih;
    INIT_TIMING(lookup_time);

    HK_START_TIMING(lookup_t, lookup_time);
    if (dentry->d_name.len > HK_NAME_LEN) {
        hk_dbg("%s: namelen %u exceeds limit\n",
               __func__, dentry->d_name.len);
        return ERR_PTR(-ENAMETOOLONG);
    }

    hk_dbgv("%s: %s\n", __func__, dentry->d_name.name);
    ino = hk_inode_by_name(dir, &dentry->d_name, &ref);
    hk_dbgv("%s: ino %lu\n", __func__, ino);

    if (ino != -1) {
        inode = hk_iget(dir->i_sb, ino);
        if (inode == ERR_PTR(-ESTALE) || inode == ERR_PTR(-ENOMEM) || inode == ERR_PTR(-EACCES)) {
            hk_err(dir->i_sb,
                   "%s: get inode failed: %lu\n",
                   __func__, (unsigned long)ino);
            return ERR_PTR(-EIO);
        }
    }

    HK_END_TIMING(lookup_t, lookup_time);
    return d_splice_alias(inode, dentry);
}

static int __hk_create(struct inode *dir, struct dentry *dentry, umode_t mode,
                       bool excl, dev_t rdev, enum hk_new_inode_type type)
{
    struct inode *inode = NULL;
    int err = PTR_ERR(inode);
    struct super_block *sb = dir->i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    u32 ino;

    hk_dbgv("%s: %s\n", __func__, dentry->d_name.name);
    hk_dbgv("%s: inode %llu, dir %lu\n", __func__, ino, dir->i_ino);

    if (ENABLE_META_PACK(sb)) {
        in_pkg_param_t param;
        in_create_pkg_param_t in_create_param;
        out_pkg_param_t out_param;
        out_create_pkg_param_t out_create_param;
        obj_ref_dentry_t *ref_dentry;
        
        err = inode_mgr_alloc(sbi->inode_mgr, &ino);
        if (ino == -1)
            goto out_err;

        /* ino is initialized by create_new_inode_pkg() */
        inode = hk_create_inode(type, dir, ino, mode,
                                0, rdev, &dentry->d_name);
        if (IS_ERR(inode))
            goto out_err;

        in_create_param.create_type = CREATE_FOR_NORMAL;
        if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
            in_create_param.rdev = rdev;
        } else {
            in_create_param.rdev = 0;
        }
        in_create_param.new_ino = ino;
        param.bin = false;
        param.private = &in_create_param;
        param.cur_pkg_addr = 0;
        out_param.private = &out_create_param;

        err = create_new_inode_pkg(sbi, mode, dentry->d_name.name, HK_IH(inode), HK_IH(dir), &param, &out_param);
        if (err) {
            goto out_err;
        }

        ref_dentry = ((out_create_pkg_param_t *)out_param.private)->ref;
        err = hk_insert_dir_table(sb, HK_IH(dir), dentry->d_name.name, strlen(dentry->d_name.name), ref_dentry);
        if (err) {
            goto out_err;
        }
    } else {
        int txid;
        struct hk_dentry *direntry;
        struct hk_inode *pidir, *pi;
        u64 pi_addr = 0;

        pidir = hk_get_inode(sb, dir);
        if (!pidir)
            goto out_err;

        err = inode_mgr_alloc(sbi->inode_mgr, &ino);
        if (ino == -1)
            goto out_err;

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

        inode = hk_create_inode(type, dir, ino, mode,
                                0, rdev, &dentry->d_name);
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
    }

    d_instantiate(dentry, inode);
    unlock_new_inode(inode);

    return err;

out_err:
    hk_err(sb, "%s return %d\n", __func__, err);
    return err;
}

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
    int err = 0;
    INIT_TIMING(create_time);
    HK_START_TIMING(create_t, create_time);
    err = __hk_create(dir, dentry, mode, excl, 0, TYPE_CREATE);
    HK_END_TIMING(create_t, create_time);
    return err;
}

static int hk_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
                    dev_t rdev)
{
    int err = 0;
    INIT_TIMING(mknod_time);
    HK_START_TIMING(mknod_t, mknod_time);
    err = __hk_create(dir, dentry, mode, false, rdev, TYPE_MKNOD);
    HK_END_TIMING(mknod_t, mknod_time);
    return err;
}

static int hk_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    int err = 0;
    INIT_TIMING(mkdir_time);
    HK_START_TIMING(mkdir_t, mkdir_time);
    err = __hk_create(dir, dentry, S_IFDIR | mode, false, 0, TYPE_MKDIR);
    inc_nlink(dir);
    HK_END_TIMING(mkdir_t, mkdir_time);
    return err;
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
    struct hk_sb_info *sbi = HK_SB(sb);
    u64 sym_blk_addr = 0;
    u32 ino;
    int txid;

    INIT_TIMING(symlink_time);

    HK_START_TIMING(symlink_t, symlink_time);
    if (len + 1 > sb->s_blocksize)
        goto out;

    if (ENABLE_META_PACK(sb)) {
        out_pkg_param_t out_param_for_data;
        out_pkg_param_t out_param_for_create;
        out_create_pkg_param_t create_out_param_for_create;
        obj_ref_dentry_t *ref_dentry;
        
        err = inode_mgr_alloc(sbi->inode_mgr, &ino);
        if (ino == -1)
            goto out_fail;

        out_param_for_create.private = &create_out_param_for_create;

        inode = hk_create_inode(TYPE_SYMLINK, dir, ino, S_IFLNK | 0777,
                                len, 0, &dentry->d_name);
        if (IS_ERR(inode)) {
            err = PTR_ERR(inode);
            goto out_fail;
        }

        err = hk_block_symlink(sb, inode, symname, len, &sym_blk_addr);
        if (err)
            goto out_fail;

        create_symlink_pkg(sbi, inode->i_mode, dentry->d_name.name, symname, ino, sym_blk_addr, HK_IH(inode), HK_IH(dir), &out_param_for_data, &out_param_for_create);

        ref_dentry = ((out_create_pkg_param_t *)out_param_for_create.private)->ref;
        err = hk_insert_dir_table(sb, HK_IH(dir), dentry->d_name.name, strlen(dentry->d_name.name), ref_dentry);
        if (err) {
            goto out_fail;
        }

    } else {
        struct hk_inode *pidir, *pi;
        struct hk_dentry *direntry;

        pidir = hk_get_inode(sb, dir);
        if (!pidir)
            goto out_fail;

        err = inode_mgr_alloc(sbi->inode_mgr, &ino);
        if (ino == 0)
            goto out_fail;

        hk_dbgv("%s: name %s, symname %s\n", __func__,
                dentry->d_name.name, symname);
        hk_dbgv("%s: inode %llu, dir %lu\n", __func__, ino, dir->i_ino);

#ifndef CONFIG_FINEGRAIN_JOURNAL
        txid = hk_start_tx_for_symlink(sb, ino, dentry, dir, S_IFLNK | 0777, symname, len);
        if (txid < 0) {
            err = txid;
            goto out_fail;
        }
#endif

        err = hk_add_dentry(dentry, ino, 0, &direntry);
        if (err)
            goto out_fail;

        inode = hk_create_inode(TYPE_SYMLINK, dir, ino, S_IFLNK | 0777,
                                len, 0, &dentry->d_name);
        if (IS_ERR(inode)) {
            err = PTR_ERR(inode);
            goto out_fail;
        }

        pi = hk_get_inode(sb, inode);

        si = HK_I(inode);
        sih = si->header;

        err = hk_block_symlink(sb, inode, symname, len, &sym_blk_addr);
        if (err)
            goto out_fail;

#ifdef CONFIG_FINEGRAIN_JOURNAL
        txid = hk_start_tx_for_symlink(sb, ino, direntry, dir, S_IFLNK | 0777, sym_blk_addr);
        if (txid < 0) {
            err = txid;
            goto out_fail;
        }
        hk_commit_newattr_indram(sb, dir);
        hk_commit_sizechange(sb, inode, len);
#endif

        hk_finish_tx(sb, txid);

    }

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
    struct hk_sb_info *sbi = HK_SB(sb);
    struct inode *inode = dest_dentry->d_inode;
    int err = -ENOMEM;
    int txid;
    INIT_TIMING(link_time);

    HK_START_TIMING(link_t, link_time);
    if (inode->i_nlink >= HK_LINK_MAX) {
        err = -EMLINK;
        goto out;
    }

    ihold(inode);

    hk_dbgv("%s: name %s, dest %s\n", __func__,
            dentry->d_name.name, dest_dentry->d_name.name);
    hk_dbgv("%s: inode %lu, dir %lu\n", __func__,
            inode->i_ino, dir->i_ino);

    if (ENABLE_META_PACK(sb)) {
        in_pkg_param_t param;
        in_create_pkg_param_t private;
        out_pkg_param_t out_param;
        out_create_pkg_param_t out_create_param;
        obj_ref_dentry_t *ref_dentry;
        struct hk_inode_info_header *sih;

        sih = hk_alloc_hk_inode_info_header();
        if (!sih) {
            err = -ENOMEM;
            goto out;
        }

        hk_init_header(sb, sih, inode->i_mode);
        sih->si = NULL;
        sih->i_flags = hk_mask_flags(inode->i_mode, dir->i_flags);

        err = inode_mgr_alloc(sbi->inode_mgr, (u32 *)&sih->ino);
        if (sih->ino == -1) {
            goto out;
        }

        private.create_type = CREATE_FOR_LINK;
        private.rdev = 0;
        private.new_ino = sih->ino;
        private.old_ino = inode->i_ino;
        param.private = &private;
        param.bin = false;
        param.cur_pkg_addr = 0;
        out_param.private = &out_create_param;

        err = create_new_inode_pkg(sbi, inode->i_mode, dest_dentry->d_name.name, sih, HK_IH(dir), &param, &out_param);
        if (err) {
            goto out;
        }

        ref_dentry = ((out_create_pkg_param_t *)out_param.private)->ref;
        err = hk_insert_dir_table(sb, HK_IH(dir), dentry->d_name.name, strlen(dentry->d_name.name), ref_dentry);
        if (err) {
            goto out;
        }
        inode->i_ctime = current_time(inode);
        inc_nlink(inode);
        BUG_ON(ref_dentry->target_ino != inode->i_ino);
    } else {
        struct hk_inode *pidir;
        struct hk_dentry *direntry;
        pidir = hk_get_inode(sb, dir);

        if (!pidir) {
            err = -EINVAL;
            goto out;
        }

#ifndef CONFIG_FINEGRAIN_JOURNAL
        txid = hk_start_tx_for_new_inode(sb, inode->i_ino, dentry, dir, S_IFLNK | 0777, 0);
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

        hk_insert_dir_table(sb, HK_IH(dir), dest_dentry->d_name.name, strlen(dest_dentry->d_name.name), direntry);
#ifdef CONFIG_FINEGRAIN_JOURNAL
        txid = hk_start_tx_for_new_inode(sb, inode->i_ino, direntry, dir, S_IFLNK | 0777, 0);
        if (txid < 0) {
            err = txid;
            iput(inode);
            goto out;
        }
        hk_commit_newattr_indram(sb, dir);
#endif
        hk_commit_linkchange_indram(sb, inode);
        hk_finish_tx(sb, txid);
    }

    d_instantiate(dentry, inode);

out:
    HK_END_TIMING(link_t, link_time);
    return err;
}

static int __hk_remove(struct inode *dir, struct dentry *dentry)
{
    struct inode *inode = dentry->d_inode;
    struct super_block *sb = dir->i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    int retval = -ENOMEM;

    if (ENABLE_META_PACK(sb)) {
        obj_ref_dentry_t *ref;
        struct hk_inode_info_header *sih;
        struct hk_inode_info_header *psih;
        in_pkg_param_t in_param;
        out_pkg_param_t out_param;

        sih = HK_IH(inode);
        psih = HK_IH(dir);

        hk_dbgv("%s: remove %lu from %lu\n", __func__, sih->ino, psih->ino);
        
        retval = hk_remove_dir_table(sb, psih, dentry->d_name.name, strlen(dentry->d_name.name), (void *)&ref);
        if (retval)
            goto out_err;
        
        inode->i_ctime = dir->i_ctime;
        
        if (inode->i_nlink)
            drop_nlink(inode);

        in_param.bin = false;
        in_param.cur_pkg_addr = 0;
        create_unlink_pkg(sbi, sih, psih, ref, &in_param, &out_param);

        hk_free_obj_ref_dentry(ref);
    } else {
        int txid;
        struct hk_inode *pi = hk_get_inode(sb, inode);
        struct hk_inode *pidir;
        struct hk_dentry *direntry;
        bool invalidate = false;
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
    }

    return 0;

out_err:
    hk_err(sb, "%s return %d\n", __func__, retval);
    return retval;
}

static int hk_unlink(struct inode *dir, struct dentry *dentry)
{
    int retval = -ENOMEM;
    INIT_TIMING(unlink_time);
    HK_START_TIMING(unlink_t, unlink_time);
    retval = __hk_remove(dir, dentry);
    HK_END_TIMING(unlink_t, unlink_time);
    return retval;
}

/*
 * routine to check that the specified directory is empty (for rmdir)
 */
static bool hk_empty_dir(struct inode *inode)
{
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    unsigned bkt;
    struct hk_dentry_info *cur;

    hash_for_each(sih->dirs, bkt, cur, node)
    {
        return false;
    }

    return true;
}

static int hk_rmdir(struct inode *dir, struct dentry *dentry)
{
    struct inode *inode = dentry->d_inode;
    int retval = -ENOTEMPTY;

    if (hk_empty_dir(inode)) {
        retval = __hk_remove(dir, dentry);
    }

    return retval;
}

static int hk_rename(struct inode *old_dir,
                     struct dentry *old_dentry,
                     struct inode *new_dir, struct dentry *new_dentry,
                     unsigned int flags)
{
    struct inode *old_inode = old_dentry->d_inode;
    struct inode *new_inode = new_dentry->d_inode;
    struct super_block *sb = old_inode->i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    int err = 0;
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

    /* FIXME: add droplink */
    if (ENABLE_META_PACK(sb)) {
        struct hk_inode_info_header *psih = HK_IH(old_dir);
        struct hk_inode_info_header *npsih = HK_IH(new_dir);
        struct hk_inode_info_header *sih = HK_IH(old_inode);
        out_pkg_param_t out_param_for_unlink;
        out_pkg_param_t out_param_for_create;
        out_create_pkg_param_t create_out_param_for_create;
        obj_ref_dentry_t *ref_dentry, *new_ref_dentry;

        out_param_for_create.private = &create_out_param_for_create;
        err = hk_remove_dir_table(sb, psih, old_dentry->d_name.name, strlen(old_dentry->d_name.name), (void *)&ref_dentry);
        if (err) {
            return err;
        }

        create_rename_pkg(sbi, new_dentry->d_name.name, ref_dentry, sih, psih, npsih, &out_param_for_unlink, &out_param_for_create);

        new_ref_dentry = ((out_create_pkg_param_t *)out_param_for_create.private)->ref;
        err = hk_insert_dir_table(sb, npsih, new_dentry->d_name.name, strlen(new_dentry->d_name.name), new_ref_dentry);
        ref_dentry_destroy(ref_dentry);
    } else {
        struct hk_inode *old_pi = NULL, *new_pi = NULL;
        struct hk_inode *new_pidir = NULL, *old_pidir = NULL;
        struct hk_dentry *father_entry = NULL;
        struct hk_dentry *father_entryc, entry_copy;
        struct hk_dentry *pd, *pd_new;
        int invalidate_new_inode = 0;
        int inc_link = 0, dec_link = 0;

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
    }

    HK_END_TIMING(rename_t, rename_time);
    return 0;

out:
    hk_err(sb, "%s return %d\n", __func__, err);
    HK_END_TIMING(rename_t, rename_time);
    return err;
}

const struct inode_operations hk_dir_inode_operations = {
    .create = hk_create,
    .lookup = hk_lookup,
    .link = hk_link,
    .unlink = hk_unlink,
    .symlink = hk_symlink,
    .mkdir = hk_mkdir,
    .rmdir = hk_rmdir,
    .mknod = hk_mknod,
    .rename = hk_rename,
    .setattr = hk_notify_change,
    .get_acl = NULL,
};

const struct inode_operations hk_special_inode_operations = {
    .setattr = hk_notify_change,
    .get_acl = NULL,
};
