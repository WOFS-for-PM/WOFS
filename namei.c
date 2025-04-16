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

#include "wofs.h"

struct wofs_dentry *wofs_dentry_by_ix_from_blk(u64 blk_addr, u16 ix)
{
    return (struct wofs_dentry *)(blk_addr + ix * sizeof(struct wofs_dentry));
}

void *wofs_search_dir_table(struct super_block *sb, struct wofs_inode_info_header *sih, const char *name, int namelen)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    void *cur = NULL;
    unsigned long hash;

    hash = BKDRHash(name, namelen);

    obj_ref_dentry_t *ref_dentry = NULL;
    struct wofs_obj_dentry *dentry;
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

    return cur;
}

int wofs_insert_dir_table(struct super_block *sb, struct wofs_inode_info_header *sih, const char *name,
                        int namelen, void *direntry)
{
    obj_ref_dentry_t *ref_dentry = direntry;
    wofs_dbgv("%s: insert %s hash %lu\n", __func__, name, ref_dentry->hash);
    hash_add(sih->dirs, &ref_dentry->hnode, ref_dentry->hash);

    return 0;
}

void wofs_destory_dir_table(struct super_block *sb, struct wofs_inode_info_header *sih)
{
    struct hlist_node *tmp;
    int bkt;
    obj_ref_dentry_t *ref_dentry;

    hash_for_each_safe(sih->dirs, bkt, tmp, ref_dentry, hnode)
    {
        hash_del(&ref_dentry->hnode);
    }
}

/* if *ret_entry is not null, the caller hold the obj */
int wofs_remove_dir_table(struct super_block *sb, struct wofs_inode_info_header *sih,
                        const char *name, int namelen, void **ret_entry)
{
    struct hlist_node *tmp;
    unsigned long hash;
    int is_find = 0;
    int searches = 0;
    INIT_TIMING(time);

    hash = BKDRHash(name, namelen);

    struct wofs_sb_info *sbi = WOFS_SB(sb);
    obj_ref_dentry_t *ref_dentry;
    struct wofs_obj_dentry *dentry;

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

    if (searches > 500) {
        wofs_warn("%s: Too many entry under the same entries %d\n", __func__, searches);
    }
    return is_find ? 0 : -ENOENT;
}

static ino_t wofs_inode_by_name(struct inode *dir, struct qstr *entry,
                              void **ret_entry)
{
    struct super_block *sb = dir->i_sb;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_inode_info *si = WOFS_I(dir);
    struct wofs_inode_info_header *sih = si->header;
    ino_t ino;
    const char *name;
    unsigned long name_len;

    name = entry->name;
    name_len = entry->len;

    obj_ref_dentry_t *ref_dentry;
    ref_dentry = wofs_search_dir_table(sb, sih, name, name_len);
    if (!ref_dentry) {
        wofs_dbgv("%s: %s not found\n", __func__, name);
        return -1;
    }

    ino = ref_dentry->target_ino;
    if (ret_entry)
        *ret_entry = ref_dentry;

    return ino;
}

struct dentry *wofs_get_parent(struct dentry *child)
{
    struct inode *inode;
    ino_t ino;

    ino = child->d_parent->d_inode->i_ino;

    if (ino)
        inode = wofs_iget(child->d_inode->i_sb, ino);
    else
        return ERR_PTR(-ENOENT);

    return d_obtain_alias(inode);
}

static struct dentry *wofs_lookup(struct inode *dir, struct dentry *dentry,
                                unsigned int flags)
{
    struct inode *inode = NULL;
    void *ref;
    ino_t ino;
    struct wofs_inode_info_header *sih;
    INIT_TIMING(lookup_time);

    WOFS_START_TIMING(lookup_t, lookup_time);
    if (dentry->d_name.len > WOFS_NAME_LEN) {
        wofs_dbg("%s: namelen %u exceeds limit\n",
               __func__, dentry->d_name.len);
        return ERR_PTR(-ENAMETOOLONG);
    }

    wofs_dbgv("%s: %s\n", __func__, dentry->d_name.name);
    ino = wofs_inode_by_name(dir, &dentry->d_name, &ref);
    wofs_dbgv("%s: ino %lu\n", __func__, ino);

    if (ino != -1) {
        inode = wofs_iget(dir->i_sb, ino);
        if (inode == ERR_PTR(-ESTALE) || inode == ERR_PTR(-ENOMEM) || inode == ERR_PTR(-EACCES)) {
            wofs_err(dir->i_sb,
                   "%s: get inode failed: %lu\n",
                   __func__, (unsigned long)ino);
            return ERR_PTR(-EIO);
        }
    }

    WOFS_END_TIMING(lookup_t, lookup_time);
    return d_splice_alias(inode, dentry);
}

static int __wofs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
                       bool excl, dev_t rdev, enum wofs_new_inode_type type)
{
    struct inode *inode = NULL;
    int err = PTR_ERR(inode);
    struct super_block *sb = dir->i_sb;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    u32 ino;

    wofs_dbgv("%s: %s\n", __func__, dentry->d_name.name);
    wofs_dbgv("%s: inode %llu, dir %lu\n", __func__, ino, dir->i_ino);

    in_pkg_param_t param;
    in_create_pkg_param_t in_create_param;
    out_pkg_param_t out_param;
    out_create_pkg_param_t out_create_param;
    obj_ref_dentry_t *ref_dentry;
    
    err = inode_mgr_alloc(sbi->inode_mgr, &ino);
    if (ino == -1)
        goto out_err;

    /* ino is initialized by create_new_inode_pkg() */
    inode = wofs_create_inode(type, dir, ino, mode,
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

    err = create_new_inode_pkg(sbi, mode, dentry->d_name.name, WOFS_IH(inode), WOFS_IH(dir), &param, &out_param);
    if (err) {
        goto out_err;
    }

    ref_dentry = ((out_create_pkg_param_t *)out_param.private)->ref;
    err = wofs_insert_dir_table(sb, WOFS_IH(dir), dentry->d_name.name, strlen(dentry->d_name.name), ref_dentry);
    if (err) {
        goto out_err;
    }

    d_instantiate(dentry, inode);
    unlock_new_inode(inode);

    return err;

out_err:
    wofs_err(sb, "%s return %d\n", __func__, err);
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
static int wofs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
                     bool excl)
{
    int err = 0;
    INIT_TIMING(create_time);
    WOFS_START_TIMING(create_t, create_time);
    err = __wofs_create(dir, dentry, mode, excl, 0, TYPE_CREATE);
    WOFS_END_TIMING(create_t, create_time);
    return err;
}

static int wofs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
                    dev_t rdev)
{
    int err = 0;
    INIT_TIMING(mknod_time);
    WOFS_START_TIMING(mknod_t, mknod_time);
    err = __wofs_create(dir, dentry, mode, false, rdev, TYPE_MKNOD);
    WOFS_END_TIMING(mknod_t, mknod_time);
    return err;
}

static int wofs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    int err = 0;
    INIT_TIMING(mkdir_time);
    WOFS_START_TIMING(mkdir_t, mkdir_time);
    err = __wofs_create(dir, dentry, S_IFDIR | mode, false, 0, TYPE_MKDIR);
    inc_nlink(dir);
    WOFS_END_TIMING(mkdir_t, mkdir_time);
    return err;
}

static int wofs_symlink(struct inode *dir, struct dentry *dentry,
                      const char *symname)
{
    struct super_block *sb = dir->i_sb;
    int err = -ENAMETOOLONG;
    unsigned int len = strlen(symname);
    struct inode *inode;
    struct wofs_inode_info *si;
    struct wofs_inode_info_header *sih;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    u64 sym_blk_addr = 0;
    u32 ino;
    int txid;

    INIT_TIMING(symlink_time);

    WOFS_START_TIMING(symlink_t, symlink_time);
    if (len + 1 > sb->s_blocksize)
        goto out;

    out_pkg_param_t out_param_for_data;
    out_pkg_param_t out_param_for_create;
    out_create_pkg_param_t create_out_param_for_create;
    obj_ref_dentry_t *ref_dentry;
    
    err = inode_mgr_alloc(sbi->inode_mgr, &ino);
    if (ino == -1)
        goto out_fail;

    out_param_for_create.private = &create_out_param_for_create;

    inode = wofs_create_inode(TYPE_SYMLINK, dir, ino, S_IFLNK | 0777,
                            len, 0, &dentry->d_name);
    if (IS_ERR(inode)) {
        err = PTR_ERR(inode);
        goto out_fail;
    }

    err = wofs_block_symlink(sb, inode, symname, len, &sym_blk_addr);
    if (err)
        goto out_fail;

    create_symlink_pkg(sbi, inode->i_mode, dentry->d_name.name, symname, ino, sym_blk_addr, WOFS_IH(inode), WOFS_IH(dir), &out_param_for_data, &out_param_for_create);

    ref_dentry = ((out_create_pkg_param_t *)out_param_for_create.private)->ref;
    err = wofs_insert_dir_table(sb, WOFS_IH(dir), dentry->d_name.name, strlen(dentry->d_name.name), ref_dentry);
    if (err) {
        goto out_fail;
    }

    d_instantiate(dentry, inode);
    unlock_new_inode(inode);

out:
    WOFS_END_TIMING(symlink_t, symlink_time);
    return err;

out_fail:
    wofs_err(sb, "%s return %d\n", __func__, err);
    goto out;
}

static int wofs_link(struct dentry *dest_dentry, struct inode *dir,
                   struct dentry *dentry)
{
    struct super_block *sb = dir->i_sb;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct inode *inode = dest_dentry->d_inode;
    int err = -ENOMEM;
    int txid;
    INIT_TIMING(link_time);

    WOFS_START_TIMING(link_t, link_time);
    if (inode->i_nlink >= WOFS_LINK_MAX) {
        err = -EMLINK;
        goto out;
    }

    ihold(inode);

    wofs_dbgv("%s: name %s, dest %s\n", __func__,
            dentry->d_name.name, dest_dentry->d_name.name);
    wofs_dbgv("%s: inode %lu, dir %lu\n", __func__,
            inode->i_ino, dir->i_ino);

    in_pkg_param_t param;
    in_create_pkg_param_t private;
    out_pkg_param_t out_param;
    out_create_pkg_param_t out_create_param;
    obj_ref_dentry_t *ref_dentry;
    struct wofs_inode_info_header *sih;

    sih = wofs_alloc_wofs_inode_info_header();
    if (!sih) {
        err = -ENOMEM;
        goto out;
    }

    wofs_init_header(sb, sih, inode->i_mode);
    sih->si = NULL;
    sih->i_flags = wofs_mask_flags(inode->i_mode, dir->i_flags);

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

    err = create_new_inode_pkg(sbi, inode->i_mode, dest_dentry->d_name.name, sih, WOFS_IH(dir), &param, &out_param);
    if (err) {
        goto out;
    }

    ref_dentry = ((out_create_pkg_param_t *)out_param.private)->ref;
    err = wofs_insert_dir_table(sb, WOFS_IH(dir), dentry->d_name.name, strlen(dentry->d_name.name), ref_dentry);
    if (err) {
        goto out;
    }
    inode->i_ctime = current_time(inode);
    inc_nlink(inode);
    BUG_ON(ref_dentry->target_ino != inode->i_ino);

    d_instantiate(dentry, inode);

out:
    WOFS_END_TIMING(link_t, link_time);
    return err;
}

static int __wofs_remove(struct inode *dir, struct dentry *dentry)
{
    struct inode *inode = dentry->d_inode;
    struct super_block *sb = dir->i_sb;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    int retval = -ENOMEM;

    obj_ref_dentry_t *ref;
    struct wofs_inode_info_header *sih;
    struct wofs_inode_info_header *psih;
    in_pkg_param_t in_param;
    out_pkg_param_t out_param;

    sih = WOFS_IH(inode);
    psih = WOFS_IH(dir);

    wofs_dbgv("%s: remove %lu from %lu\n", __func__, sih->ino, psih->ino);
    
    retval = wofs_remove_dir_table(sb, psih, dentry->d_name.name, strlen(dentry->d_name.name), (void *)&ref);
    if (retval)
        goto out_err;
    
    inode->i_ctime = dir->i_ctime;
    
    if (inode->i_nlink)
        drop_nlink(inode);

    in_param.bin = false;
    in_param.cur_pkg_addr = 0;
    create_unlink_pkg(sbi, sih, psih, ref, &in_param, &out_param);

    wofs_free_obj_ref_dentry(ref);

    return 0;

out_err:
    wofs_err(sb, "%s return %d\n", __func__, retval);
    return retval;
}

static int wofs_unlink(struct inode *dir, struct dentry *dentry)
{
    int retval = -ENOMEM;
    INIT_TIMING(unlink_time);
    WOFS_START_TIMING(unlink_t, unlink_time);
    retval = __wofs_remove(dir, dentry);
    WOFS_END_TIMING(unlink_t, unlink_time);
    return retval;
}

/*
 * routine to check that the specified directory is empty (for rmdir)
 */
static bool wofs_empty_dir(struct inode *inode)
{
    struct wofs_inode_info *si = WOFS_I(inode);
    struct wofs_inode_info_header *sih = si->header;
    unsigned bkt;
    struct wofs_dentry_info *cur;

    hash_for_each(sih->dirs, bkt, cur, node)
    {
        return false;
    }

    return true;
}

static int wofs_rmdir(struct inode *dir, struct dentry *dentry)
{
    struct inode *inode = dentry->d_inode;
    int retval = -ENOTEMPTY;

    if (wofs_empty_dir(inode)) {
        retval = __wofs_remove(dir, dentry);
    }

    return retval;
}

static int wofs_rename(struct inode *old_dir,
                     struct dentry *old_dentry,
                     struct inode *new_dir, struct dentry *new_dentry,
                     unsigned int flags)
{
    struct inode *old_inode = old_dentry->d_inode;
    struct inode *new_inode = new_dentry->d_inode;
    struct super_block *sb = old_inode->i_sb;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    int err = 0;
    unsigned long irq_flags = 0;
    int txid;

    INIT_TIMING(rename_time);

    wofs_dbgv("%s: rename %s to %s,\n", __func__,
            old_dentry->d_name.name, new_dentry->d_name.name);
    wofs_dbgv("%s: %s inode %lu, old dir %lu, new dir %lu, new inode %lu\n",
            __func__, S_ISDIR(old_inode->i_mode) ? "dir" : "normal",
            old_inode->i_ino, old_dir->i_ino, new_dir->i_ino,
            new_inode ? new_inode->i_ino : 0);

    if (flags & ~RENAME_NOREPLACE)
        return -EINVAL;

    WOFS_START_TIMING(rename_t, rename_time);

    if (new_inode) {
        err = -ENOTEMPTY;
        if (S_ISDIR(old_inode->i_mode) && !wofs_empty_dir(new_inode))
            goto out;
    } else {
        if (S_ISDIR(old_inode->i_mode)) {
            err = -EMLINK;
            if (new_dir->i_nlink >= WOFS_LINK_MAX)
                goto out;
        }
    }

    /* FIXME: add droplink */
    struct wofs_inode_info_header *psih = WOFS_IH(old_dir);
    struct wofs_inode_info_header *npsih = WOFS_IH(new_dir);
    struct wofs_inode_info_header *sih = WOFS_IH(old_inode);
    out_pkg_param_t out_param_for_unlink;
    out_pkg_param_t out_param_for_create;
    out_create_pkg_param_t create_out_param_for_create;
    obj_ref_dentry_t *ref_dentry, *new_ref_dentry;

    out_param_for_create.private = &create_out_param_for_create;
    err = wofs_remove_dir_table(sb, psih, old_dentry->d_name.name, strlen(old_dentry->d_name.name), (void *)&ref_dentry);
    if (err) {
        return err;
    }

    create_rename_pkg(sbi, new_dentry->d_name.name, ref_dentry, sih, psih, npsih, &out_param_for_unlink, &out_param_for_create);

    new_ref_dentry = ((out_create_pkg_param_t *)out_param_for_create.private)->ref;
    err = wofs_insert_dir_table(sb, npsih, new_dentry->d_name.name, strlen(new_dentry->d_name.name), new_ref_dentry);
    ref_dentry_destroy(ref_dentry);

    WOFS_END_TIMING(rename_t, rename_time);
    return 0;

out:
    wofs_err(sb, "%s return %d\n", __func__, err);
    WOFS_END_TIMING(rename_t, rename_time);
    return err;
}

const struct inode_operations wofs_dir_inode_operations = {
    .create = wofs_create,
    .lookup = wofs_lookup,
    .link = wofs_link,
    .unlink = wofs_unlink,
    .symlink = wofs_symlink,
    .mkdir = wofs_mkdir,
    .rmdir = wofs_rmdir,
    .mknod = wofs_mknod,
    .rename = wofs_rename,
    .setattr = wofs_notify_change,
    .get_acl = NULL,
};

const struct inode_operations wofs_special_inode_operations = {
    .setattr = wofs_notify_change,
    .get_acl = NULL,
};
