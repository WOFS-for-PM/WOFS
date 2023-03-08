/*
 * BRIEF DESCRIPTION
 *
 * HUNTER Inode methods (allocate/free/read/write).
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

#ifndef CONFIG_PERCORE_IALLOCATOR
int hk_init_free_inode_list(struct super_block *sb, bool is_init)
{
    struct hk_inode *pi;
    struct hk_sb_info *sbi = HK_SB(sb);
    inode_mgr_t *mgr = sbi->inode_mgr;
    imap_t *imap = &sbi->pack_layout.obj_mgr.prealloc_imap;
    struct hlist_head *map = imap->map;
    struct hk_inode_info_header *cur;
    int bkt;
    int i;

    if (is_init) {
        hk_range_insert_range(sb, &mgr->ilist, 0, HK_NUM_INO - 1);
    } else {
        if (ENABLE_META_PACK(sb)) {
            /* First insert all values */
            hk_init_free_inode_list(sb, true);
            /* Second filter out those existing value */
            hash_for_each(map, bkt, cur, hnode)
            {
                inode_mgr_restore(mgr, cur->ino);
            }
        } else {
            for (i = HK_NUM_INO - 1; i >= 0; i--) {
                pi = hk_get_inode_by_ino(sb, i);
                if (!pi->valid) {
                    hk_range_insert_value(sb, &sbi->ilist, i);
                }
            }
        }
    }

    return 0;
}
#else
int hk_init_free_inode_list_percore(struct super_block *sb, int cpuid, bool is_init)
{
    struct hk_inode *pi;
    struct hk_sb_info *sbi = HK_SB(sb);
    inode_mgr_t *mgr = sbi->inode_mgr;
    imap_t *imap = &sbi->pack_layout.obj_mgr->prealloc_imap;
    struct hk_inode_info_header *cur;
    int bkt;
    u64 start_ino, end_ino;
    int inums_percore;
    int i;

    inums_percore = HK_NUM_INO / sbi->cpus;
    start_ino = cpuid * inums_percore;
    if (cpuid == 0) {
        start_ino = HK_RESV_NUM;
        inums_percore -= HK_RESV_NUM;
    }
    end_ino = start_ino + inums_percore - 1;

    if (is_init) {
        hk_range_insert_range(sb, &mgr->ilists[cpuid], start_ino, end_ino);
    } else {
        if (ENABLE_META_PACK(sb)) {
            /* First insert all values */
            hk_init_free_inode_list_percore(sb, cpuid, true);
            /* Second filter out those existing value */
            hash_for_each(imap->map, bkt, cur, hnode)
            {
                inode_mgr_restore(mgr, cur->ino);
            }
        } else {
            for (i = end_ino; i >= start_ino; i--) {
                pi = hk_get_inode_by_ino(sb, i);
                if (!pi->valid) {
                    hk_range_insert_value(sb, &mgr->ilists[cpuid], i);
                }
            }
        }
    }

    mgr->ilist_init[cpuid] = true;

    return 0;
}
#endif

static int hk_free_dram_resource(struct super_block *sb,
                                 struct hk_inode_info_header *sih)
{
    unsigned long last_blocknr;
    int freed = 0;

    if (sih->ino == HK_ROOT_INO) /* We should not evict ROOT INO */
        return 0;

    if (!(S_ISREG(sih->i_mode)) && !(S_ISDIR(sih->i_mode)))
        return 0;

    freed = sih->ix.num_slots;

    if (S_ISREG(sih->i_mode)) {
        linix_destroy(&sih->ix);
    } else {
        linix_destroy(&sih->ix);
        hk_destory_dir_table(sb, sih);
    }

    return freed;
}

int __hk_free_inode_blks(struct super_block *sb, struct hk_inode *pi,
                         struct hk_inode_info_header *sih)
{
    int freed = 0;
    u64 blk_addr;
    unsigned long irq_flags = 0;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_header *hdr;
    struct inode *inode;

    /* TODO: pass in hk_inode_info instead of hk_inode_info_header */
    // si = container_of(sih, struct hk_inode_info, header);
    // inode = &si->vfs_inode;
    if (ENABLE_META_PACK(sb)) {
        /* Do Nothing */
        obj_mgr_t *obj_mgr = sbi->pack_layout.obj_mgr;
        data_update_t update;

        update.ofs = 0;
        update.num = ((sih->i_size - 1) >> PAGE_SHIFT) + 1;

        hk_dbgv("free %d pages for ino %lu\n", update.num, sih->ino);
        
        while (reclaim_dram_data(obj_mgr, sih, &update) == -EAGAIN) {
            ;
        }

        freed = update.num;
    } else {
        traverse_inode_hdr(sbi, pi, hdr)
        {
            if (ENABLE_META_ASYNC(sb)) {
                blk_addr = sm_get_addr_by_hdr(sb, hdr);
                hk_invalid_hdr_background(sb, inode, blk_addr, hdr->f_blk);
            } else {
                hk_memunlock_hdr(sb, hdr, &irq_flags);
                hdr->valid = 0;
                hk_memlock_hdr(sb, hdr, &irq_flags);
                hk_flush_buffer(hdr, sizeof(struct hk_header), false);
            }
            freed += HK_PBLK_SZ(sbi);
        }
    }

    return freed;
}

int hk_free_inode_blks(struct super_block *sb, struct hk_inode *pi,
                       struct hk_inode_info_header *sih)
{
    int freed = 0;
    unsigned long irq_flags = 0;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_header *hdr;
    struct hk_layout_info *layout;
    INIT_TIMING(free_time);

    HK_START_TIMING(free_inode_log_t, free_time);

    freed = __hk_free_inode_blks(sb, pi, sih);

    HK_END_TIMING(free_inode_log_t, free_time);
    return freed;
}

static int hk_get_cpuid_by_ino(struct super_block *sb, u64 ino)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    int cpuid = 0;
    int inums_percore = HK_NUM_INO / sbi->cpus;
    cpuid = ino / inums_percore;
    return cpuid;
}

static int hk_free_inode(struct super_block *sb, struct hk_inode_info_header *sih)
{
    int err = 0;
    struct hk_sb_info *sbi = HK_SB(sb);
    INIT_TIMING(free_time);

    HK_START_TIMING(free_inode_t, free_time);

    sih->i_mode = 0;
    sih->norm_spec.pi_addr = 0;
    sih->i_size = 0;
    sih->i_blocks = 0;

    err = inode_mgr_free(sbi->inode_mgr, sih->ino);

    HK_END_TIMING(free_inode_t, free_time);
    return err;
}

static int hk_free_inode_resource(struct super_block *sb, struct hk_inode *pi,
                                  struct hk_inode_info_header *sih)
{
    int ret = 0;
    int freed = 0;
    unsigned long irq_flags = 0;

    if (ENABLE_META_PACK(sb)) {
        hk_free_inode_blks(sb, NULL, sih);
    } else {
        hk_memunlock_inode(sb, pi, &irq_flags);
        pi->valid = 0;
        if (pi->valid) {
            hk_dbg("%s: inode %lu still valid\n",
                __func__, sih->ino);
            pi->valid = 0;
        }
        hk_flush_buffer(pi, sizeof(struct hk_inode), false);
        hk_memlock_inode(sb, pi, &irq_flags);

        /* invalid blks hdr belongs to inode */
        hk_free_inode_blks(sb, pi, sih);
    }
    
    freed = hk_free_dram_resource(sb, sih);

    hk_dbg_verbose("%s: %d Blks Freed\n", __func__, freed);

    /* NOTE: we must unload sih first, or hk_create() will re-hold */ 
    /* the sih if hk_free_inode() is called first since inode number */
    /* does not be held by sih, and can be allocated. */
    if (ENABLE_META_PACK(sb)) {
        obj_mgr_t *obj_mgr = HK_SB(sb)->pack_layout.obj_mgr;
        obj_mgr_unload_imap_control(obj_mgr, sih);
    }

    sih->si->header = NULL;
    /* Then we can free the inode */
    ret = hk_free_inode(sb, sih);
    if (ret)
        hk_err(sb, "%s: free inode %lu failed\n",
               __func__, sih->ino);

    hk_free_hk_inode_info_header(sih);

    return ret;
}

/* Write back routinue, but we flush inode  */
int hk_write_inode(struct inode *inode, struct writeback_control *wbc)
{
    /* write_inode should never be called because we always keep our inodes
     */
    return 0;
}

void hk_evict_inode(struct inode *inode)
{
    struct super_block *sb = inode->i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info_header *sih = HK_IH(inode);
    INIT_TIMING(evict_time);
    int destroy = 0;
    int ret;

    HK_START_TIMING(evict_inode_t, evict_time);
    if (!sih) {
        hk_err(sb, "%s: ino %lu sih is NULL!\n",
               __func__, inode->i_ino);
        HK_ASSERT(0);
        goto out;
    }

    if (ENABLE_HISTORY_W(sb)) {
        hk_dw_forward(&sbi->dw, sih->i_size);
    }

    hk_dbgv("%s: %lu\n", __func__, inode->i_ino);
    
    if (ENABLE_META_PACK(sb)) {
        if (!inode->i_nlink && !is_bad_inode(inode)) {
            if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
                goto out;

            ret = hk_free_inode_resource(sb, NULL, sih);
            if (ret)
                goto out;

            destroy = 1;

            inode->i_mtime = inode->i_ctime = current_time(inode);
            inode->i_size = 0;
        }
    } else {
        struct hk_inode *pi = hk_get_inode(sb, inode);
        // pi can be NULL if the file has already been deleted, but a handle
        // remains.
        if (pi && pi->ino != inode->i_ino) {
            hk_err(sb, "%s: inode %lu ino does not match: %llu\n",
                __func__, inode->i_ino, pi->ino);
            hk_dbg("sih: ino %lu, inode size %lu, mode %u, inode mode %u\n",
                sih->ino, sih->i_size,
                sih->i_mode, inode->i_mode);
        }

        if (!inode->i_nlink && !is_bad_inode(inode)) {
            if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
                goto out;

            if (pi) {
                ret = hk_free_inode_resource(sb, pi, sih);
                if (ret)
                    goto out;
            }

            destroy = 1;
            pi = NULL; /* we no longer own the hk_inode */

            inode->i_mtime = inode->i_ctime = current_time(inode);
            inode->i_size = 0;
        }
    }
out:
    if (destroy == 0) {
        /* Called when umount/close */
        hk_dbgv("%s: destroying %lu\n", __func__, inode->i_ino);
        hk_free_dram_resource(sb, sih);
    }

    truncate_inode_pages(&inode->i_data, 0);

    clear_inode(inode);
    HK_END_TIMING(evict_inode_t, evict_time);
}

int hk_getattr(const struct path *path, struct kstat *stat,
               u32 request_mask, unsigned int query_flags)
{
    struct inode *inode = d_inode(path->dentry);
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    unsigned int flags = sih->i_flags;

    if (flags & FS_APPEND_FL)
        stat->attributes |= STATX_ATTR_APPEND;
    if (flags & FS_COMPR_FL)
        stat->attributes |= STATX_ATTR_COMPRESSED;
    if (flags & FS_IMMUTABLE_FL)
        stat->attributes |= STATX_ATTR_IMMUTABLE;
    if (flags & FS_NODUMP_FL)
        stat->attributes |= STATX_ATTR_NODUMP;

    generic_fillattr(inode, stat);
    /* stat->blocks should be the number of 512B blocks */
    stat->blocks = (inode->i_blocks << inode->i_sb->s_blocksize_bits) >> 9;
    return 0;
}

void hk_set_inode_flags(struct inode *inode, bool i_xattr,
                        unsigned int flags)
{
    inode->i_flags &=
        ~(S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME | S_DIRSYNC);
    if (flags & FS_SYNC_FL)
        inode->i_flags |= S_SYNC;
    if (flags & FS_APPEND_FL)
        inode->i_flags |= S_APPEND;
    if (flags & FS_IMMUTABLE_FL)
        inode->i_flags |= S_IMMUTABLE;
    if (flags & FS_NOATIME_FL)
        inode->i_flags |= S_NOATIME;
    if (flags & FS_DIRSYNC_FL)
        inode->i_flags |= S_DIRSYNC;
    if (!i_xattr)
        inode_has_no_xattr(inode);
    inode->i_flags |= S_DAX;
}

static void hk_get_inode_flags(struct inode *inode, struct hk_inode *pi)
{
    unsigned int flags = inode->i_flags;
    unsigned int hk_flags = le32_to_cpu(pi->i_flags);

    hk_flags &= ~(FS_SYNC_FL | FS_APPEND_FL | FS_IMMUTABLE_FL |
                  FS_NOATIME_FL | FS_DIRSYNC_FL);
    if (flags & S_SYNC)
        hk_flags |= FS_SYNC_FL;
    if (flags & S_APPEND)
        hk_flags |= FS_APPEND_FL;
    if (flags & S_IMMUTABLE)
        hk_flags |= FS_IMMUTABLE_FL;
    if (flags & S_NOATIME)
        hk_flags |= FS_NOATIME_FL;
    if (flags & S_DIRSYNC)
        hk_flags |= FS_DIRSYNC_FL;

    pi->i_flags = cpu_to_le32(hk_flags);
}

/* Init in-NVM inode structure */
void hk_init_inode(struct inode *inode, struct hk_inode *pi)
{
    pi->i_mode = cpu_to_le16(inode->i_mode);
    pi->i_uid = cpu_to_le32(i_uid_read(inode));
    pi->i_gid = cpu_to_le32(i_gid_read(inode));
    pi->i_links_count = cpu_to_le16(inode->i_nlink);
    pi->i_size = cpu_to_le64(inode->i_size);
    pi->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
    pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
    pi->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
    pi->i_generation = cpu_to_le32(inode->i_generation);

    pi->h_addr = cpu_to_le64(0);
#ifndef CONFIG_FINEGRAIN_JOURNAL
    pi->valid = 1; /* valid this in transactions */
#endif
    pi->tstamp = cpu_to_le64(get_version(HK_SB(inode->i_sb)));
    hk_get_inode_flags(inode, pi);

    if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
        pi->dev.rdev = cpu_to_le32(inode->i_rdev);
}

/* copy persistent state to struct inode */
static int hk_build_vfs_inode(struct super_block *sb, struct inode *inode,
                              u64 ino)
{
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    struct hk_sb_info *sbi = HK_SB(sb);
    dev_t rdev;
    int ret = -EIO;

    if (ENABLE_META_PACK(sb)) {
        u64 create_pkg_addr = get_pm_addr(sbi, sih->pack_spec.latest_fop.latest_inode->hdr.addr);
        struct hk_obj_inode *obj_inode = (struct hk_obj_inode *)create_pkg_addr;

        inode->i_mode = sih->i_mode;
        i_uid_write(inode, sih->i_uid);
        i_gid_write(inode, sih->i_gid);

        inode->i_generation = obj_inode->i_generation;
        hk_set_inode_flags(inode, obj_inode->i_xattr, le32_to_cpu(obj_inode->i_flags));

        inode->i_blocks = sih->i_blocks;
        inode->i_mapping->a_ops = &hk_aops_dax;

        /* Update size and time after rebuild the tree */
        inode->i_size = le64_to_cpu(sih->i_size);
        inode->i_atime.tv_sec = (__s32)le32_to_cpu(sih->i_atime);
        inode->i_ctime.tv_sec = (__s32)le32_to_cpu(sih->i_ctime);
        inode->i_mtime.tv_sec = (__s32)le32_to_cpu(sih->i_mtime);
        inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec =
            inode->i_ctime.tv_nsec = 0;
        set_nlink(inode, le16_to_cpu(sih->i_links_count));
        rdev = le32_to_cpu(obj_inode->dev.rdev);
    } else {
        struct hk_inode *pi;
        pi = hk_get_inode_by_ino(sb, ino);

        inode->i_mode = sih->i_mode;
        i_uid_write(inode, le32_to_cpu(pi->i_uid));
        i_gid_write(inode, le32_to_cpu(pi->i_gid));

        inode->i_generation = le32_to_cpu(pi->i_generation);
        hk_set_inode_flags(inode, pi->i_xattr, le32_to_cpu(pi->i_flags));

        inode->i_blocks = sih->i_blocks;
        inode->i_mapping->a_ops = &hk_aops_dax;

        /* Update size and time after rebuild the tree */
        inode->i_size = le64_to_cpu(sih->i_size);
        inode->i_atime.tv_sec = (__s32)le32_to_cpu(pi->i_atime);
        inode->i_ctime.tv_sec = (__s32)le32_to_cpu(pi->i_ctime);
        inode->i_mtime.tv_sec = (__s32)le32_to_cpu(pi->i_mtime);
        inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec =
            inode->i_ctime.tv_nsec = 0;
        set_nlink(inode, le16_to_cpu(pi->i_links_count));
        rdev = le32_to_cpu(pi->dev.rdev);
    }

    switch (inode->i_mode & S_IFMT) {
    case S_IFREG:
        inode->i_op = &hk_file_inode_operations;
        inode->i_fop = &hk_dax_file_operations;
        break;
    case S_IFDIR:
        inode->i_op = &hk_dir_inode_operations;
        inode->i_fop = &hk_dir_operations;
        break;
    case S_IFLNK:
        inode->i_op = &hk_symlink_inode_operations;
        break;
    default:
        inode->i_op = &hk_special_inode_operations;
        init_special_inode(inode, inode->i_mode, rdev);
        break;
    }

    return 0;

bad_inode:
    make_bad_inode(inode);
    return ret;
}

#if 0
u64 hk_get_new_ino(struct super_block *sb)
{
    u64 ino = (u64)-1;
    struct hk_sb_info *sbi = HK_SB(sb);
	u64 len = 1;

    INIT_TIMING(new_hk_ino_time);

    HK_START_TIMING(new_HK_inode_t, new_hk_ino_time);

#ifndef CONFIG_PERCORE_IALLOCATOR
    mutex_lock(&sbi->ilist_lock);
    if (unlikely(list_empty(&sbi->ilist))) {
        hk_init_free_inode_list(sb, false);
    }
    ino = hk_range_pop(&sbi->ilist);
    mutex_unlock(&sbi->ilist_lock);
#else
    int cpuid, start_cpuid;

    cpuid = hk_get_cpuid(sb);
    start_cpuid = cpuid;

    do {
        mutex_lock(&sbi->ilist_locks[cpuid]);
        if (unlikely(sbi->ilist_init[cpuid] == false)) {
            hk_init_free_inode_list_percore(sb, cpuid, false);
        }
        if (!list_empty(&sbi->ilists[cpuid])) {
            ino = hk_range_pop(&sbi->ilists[cpuid], &len);
            mutex_unlock(&sbi->ilist_locks[cpuid]);
            break;
        }
        mutex_unlock(&sbi->ilist_locks[cpuid]);
        cpuid = (cpuid + 1) % sbi->cpus;
    } while (cpuid != start_cpuid);

#endif
    if (ino == (u64)-1) {
        hk_info("No free inode\n");
        BUG_ON(1);
    }

    HK_END_TIMING(new_HK_inode_t, new_hk_ino_time);
    return ino;
}
#endif

/* lazy allocator */
int inode_mgr_init(struct hk_sb_info *sbi, inode_mgr_t *mgr)
{
    int i, cpus = sbi->cpus;
    mgr->sbi = sbi;
    /* Inode List Related */
#ifndef CONFIG_PERCORE_IALLOCATOR
    INIT_LIST_HEAD(&mgr->ilist);
    spin_lock_init(&mgr->ilist_lock);
#else
    mgr->ilists = kcalloc(cpus, sizeof(struct list_head), GFP_KERNEL);
    for (i = 0; i < cpus; i++)
        INIT_LIST_HEAD(&mgr->ilists[i]);
    mgr->ilist_locks = kcalloc(cpus, sizeof(spinlock_t), GFP_KERNEL);
    for (i = 0; i < cpus; i++)
        spin_lock_init(&mgr->ilist_locks[i]);
    mgr->ilist_init = kcalloc(cpus, sizeof(bool), GFP_KERNEL);
    for (i = 0; i < cpus; i++)
        mgr->ilist_init[i] = false;
#endif
    return 0;
}

int inode_mgr_alloc(inode_mgr_t *mgr, u32 *ret_ino)
{
    u32 ino = (u32)-1;
    struct hk_sb_info *sbi = mgr->sbi;
    struct super_block *sb = sbi->sb;
    u64 len = 1;

    INIT_TIMING(new_hk_ino_time);

    HK_START_TIMING(new_HK_inode_t, new_hk_ino_time);

#ifndef CONFIG_PERCORE_IALLOCATOR
    spin_lock(&mgr->ilist_lock);
    if (unlikely(list_empty(&mgr->ilist))) {
        hk_init_free_inode_list(sb, false);
    }
    ino = hk_range_pop(&mgr->ilist);
    spin_unlock(&mgr->ilist_lock);
#else
    int cpuid, start_cpuid;

    cpuid = hk_get_cpuid(sb);
    start_cpuid = cpuid;

    do {
        spin_lock(&mgr->ilist_locks[cpuid]);
        if (unlikely(mgr->ilist_init[cpuid] == false)) {
            hk_init_free_inode_list_percore(sb, cpuid, false);
        }
        if (!list_empty(&mgr->ilists[cpuid])) {
            ino = hk_range_pop(&mgr->ilists[cpuid], &len);
            spin_unlock(&mgr->ilist_locks[cpuid]);
            break;
        }
        spin_unlock(&mgr->ilist_locks[cpuid]);
        cpuid = (cpuid + 1) % sbi->cpus;
    } while (cpuid != start_cpuid);

#endif
    if (ino == (u32)-1) {
        hk_info("No free inode\n");
        BUG_ON(1);
    }

    if (ret_ino)
        *ret_ino = ino;

    HK_END_TIMING(new_HK_inode_t, new_hk_ino_time);
    return 0;
}

int inode_mgr_free(inode_mgr_t *mgr, u32 ino)
{
    struct hk_sb_info *sbi = mgr->sbi;
    struct super_block *sb = sbi->sb;
    int err = 0;

#ifndef CONFIG_PERCORE_IALLOCATOR
    spin_lock(&mgr->ilist_lock);
    err = hk_range_insert_value(sb, &mgr->ilist, ino);
    spin_unlock(&mgr->ilist_lock);
#else
    int cpuid;
    cpuid = hk_get_cpuid_by_ino(sb, ino);
    spin_lock(&mgr->ilist_locks[cpuid]);
    err = hk_range_insert_value(sb, &mgr->ilists[cpuid], ino);
    spin_unlock(&mgr->ilist_locks[cpuid]);
#endif

    return err;
}

int inode_mgr_restore(inode_mgr_t *mgr, u32 ino)
{
    struct hk_sb_info *sbi = mgr->sbi;
    struct super_block *sb = sbi->sb;
    int err = 0;

#ifndef CONFIG_PERCORE_IALLOCATOR
    spin_lock(&mgr->ilist_lock);
    err = hk_range_remove(sb, &mgr->ilist, ino);
    spin_unlock(&mgr->ilist_lock);
#else
    int cpuid;
    cpuid = hk_get_cpuid_by_ino(sb, ino);
    spin_lock(&mgr->ilist_locks[cpuid]);
    err = hk_range_remove(sb, &mgr->ilists[cpuid], ino);
    spin_unlock(&mgr->ilist_locks[cpuid]);
#endif
    return err;
}

int inode_mgr_destroy(inode_mgr_t *mgr)
{
    struct hk_sb_info *sbi = mgr->sbi;
    if (mgr) {
#ifndef CONFIG_PERCORE_IALLOCATOR
        hk_range_free_all(&mgr->ilist);
#else
        int cpuid;
        for (cpuid = 0; cpuid < sbi->cpus; cpuid++) {
            hk_range_free_all(&mgr->ilists[cpuid]);
        }
#endif
        kfree(mgr);
    }
    return 0;
}

struct inode *hk_create_inode(enum hk_new_inode_type type, struct inode *dir,
                              u64 ino, umode_t mode, size_t size, dev_t rdev,
                              const struct qstr *qstr)
{
    struct super_block *sb;
    struct hk_sb_info *sbi;
    struct inode *inode;
    struct hk_inode_info *si;
    struct hk_inode_info_header *sih = NULL;
    int errval;
    unsigned int i_flags;
    unsigned long i_xattr = 0;
    unsigned long irq_flags = 0;
    INIT_TIMING(new_inode_time);

    HK_START_TIMING(new_vfs_inode_t, new_inode_time);
    sb = dir->i_sb;
    sbi = (struct hk_sb_info *)sb->s_fs_info;
    inode = new_inode(sb);
    if (!inode) {
        errval = -ENOMEM;
        goto fail2;
    }
    
    inode_init_owner(inode, dir, mode);
    inode->i_blocks = inode->i_size = 0;
    inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);

    inode->i_generation = atomic_add_return(1, &sbi->next_generation);
    inode->i_size = size;
    inode->i_mode = mode;

    /* chosen inode is in ino */
    if (ino == 0) {
        hk_dbg("%s: create inode without ino initialized\n", __func__);
        BUG_ON(1);
    } else {
        inode->i_ino = ino;
    }

    switch (type) {
    case TYPE_CREATE:
        inode->i_op = &hk_file_inode_operations;
        inode->i_mapping->a_ops = &hk_aops_dax;
        inode->i_fop = &hk_dax_file_operations;
        break;
    case TYPE_MKNOD:
        init_special_inode(inode, mode, rdev);
        inode->i_op = &hk_special_inode_operations;
        break;
    case TYPE_SYMLINK:
        inode->i_op = &hk_symlink_inode_operations;
        inode->i_mapping->a_ops = &hk_aops_dax;
        break;
    case TYPE_MKDIR:
        inode->i_op = &hk_dir_inode_operations;
        inode->i_fop = &hk_dir_operations;
        inode->i_mapping->a_ops = &hk_aops_dax;
        set_nlink(inode, 2);
        break;
    default:
        hk_dbg("Unknown new inode type %d\n", type);
        break;
    }

    i_flags = hk_mask_flags(mode, dir->i_flags);
    si = HK_I(inode);
    sih = si->header;
    if (!sih) {
        sih = hk_alloc_hk_inode_info_header();
        if (!sih) {
            errval = -ENOMEM;
            goto fail1;
        }
        hk_dbgv("%s: allocate new sih for inode %llu\n", __func__, ino);
        si->header = sih;
    }
    hk_init_header(sb, sih, inode->i_mode);
    sih->ino = ino;
    sih->si = si;
    sih->i_flags = le32_to_cpu(i_flags);

    if (ENABLE_META_PACK(sb)) {
        i_xattr = 0;
        sih->i_uid = i_uid_read(inode);
        sih->i_gid = i_gid_read(inode);
    } else {
        struct hk_inode *diri = NULL;
        struct hk_inode *pi;

        diri = hk_get_inode(sb, dir);
        if (!diri) {
            errval = -EACCES;
            goto fail1;
        }

        pi = (struct hk_inode *)hk_get_inode_by_ino(sb, ino);
        hk_dbg_verbose("%s: allocating inode %llu @ 0x%llx\n",
                       __func__, ino, (u64)pi);

        hk_memunlock_inode(sb, pi, &irq_flags);
        pi->i_flags = hk_mask_flags(mode, diri->i_flags);
        pi->ino = ino;
        pi->i_create_time = current_time(inode).tv_sec;
        hk_init_inode(inode, pi);
        hk_flush_buffer(pi, sizeof(struct hk_inode), false);
        hk_memlock_inode(sb, pi, &irq_flags);

        sih->norm_spec.pi_addr = (u64)pi;
        sih->norm_spec.tstamp = le64_to_cpu(pi->tstamp);
        i_xattr = 0;
    }

    hk_set_inode_flags(inode, i_xattr, le32_to_cpu(i_flags));

    if (insert_inode_locked(inode) < 0) {
        hk_dbg("hk_new_inode failed ino %lx\n", inode->i_ino);
        errval = -EINVAL;
        goto fail1;
    }

    HK_END_TIMING(new_vfs_inode_t, new_inode_time);
    return inode;

fail1:
    make_bad_inode(inode);
    iput(inode);

fail2:
    HK_END_TIMING(new_vfs_inode_t, new_inode_time);
    return ERR_PTR(errval);
}

static int hk_handle_setattr_operation(struct super_block *sb, struct inode *inode,
                                       unsigned int ia_valid, struct iattr *attr)
{
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    struct hk_sb_info *sbi = HK_SB(sb);
    int ret = 0;

    if (ia_valid & ATTR_MODE)
        sih->i_mode = inode->i_mode;
    if (ENABLE_META_PACK(sb)) {
        in_pkg_param_t param;
        out_pkg_param_t out_param;

        ret = create_attr_pkg(sbi, sih, 0, attr->ia_size - inode->i_size,
                              &param, &out_param);
    } else {
        ret = hk_commit_sizechange(sb, inode, attr->ia_size);
    }

    return ret;
}

/*
 * Zero the tail page. Used in resize request
 * to avoid to keep data in case the file grows again.
 */
void hk_prepare_truncate(struct super_block *sb,
                         struct inode *inode, loff_t newsize)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    u64 addr;
    unsigned long offset = newsize & (sb->s_blocksize - 1);
    unsigned long index, length;
    unsigned long irq_flags = 0;

    if (offset == 0 || newsize > inode->i_size)
        return;

    length = sb->s_blocksize - offset;
    index = newsize >> sb->s_blocksize_bits;

    if (ENABLE_META_PACK(sb)) {
        obj_ref_data_t *ref = NULL;
        ref = (obj_ref_data_t *)hk_inode_get_slot(sih, index << PAGE_SHIFT);
        addr = get_pm_addr_by_data_ref(sbi, ref, index << PAGE_SHIFT);
    } else {
        addr = TRANS_OFS_TO_ADDR(sbi, (u64)hk_inode_get_slot(sih, index << PAGE_SHIFT));
    }

    if (addr == 0)
        return;

    hk_memunlock_range(sb, addr + offset, length, &irq_flags);
    memset_nt(addr + offset, 0, length);
    hk_memlock_range(sb, addr + offset, length, &irq_flags);
}

/*
 * Free data blocks from inode in the range start <=> end
 */
static void hk_truncate_file_blocks(struct inode *inode, loff_t start, loff_t end)
{
    struct super_block *sb = inode->i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode *pi = hk_get_inode(sb, inode);
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    unsigned int data_bits = sb->s_blocksize_bits;
    s64 start_index, end_index, index;
    u64 addr;
    int freed = 0;

    // TODO: We're not handle holes in the file
    inode->i_mtime = inode->i_ctime = current_time(inode);

    hk_dbg_verbose("truncate: pi %p iblocks %lx %llx %llx %llx\n", pi,
                   sih->i_blocks, start, end, pi->i_size);

    start_index = (start + (1UL << data_bits) - 1) >> data_bits;

    if (end == 0)
        return;
    end_index = (end - 1) >> data_bits;

    if (start_index > end_index)
        return;

    if (ENABLE_META_PACK(sb)) {
        obj_mgr_t *obj_mgr = sbi->pack_layout.obj_mgr;
        data_update_t update;

        update.ofs = start_index << PAGE_SHIFT;
        update.num = end_index - start_index + 1;

        while (reclaim_dram_data(obj_mgr, sih, &update) == -EAGAIN) {
            ;
        }

        freed = update.num;
    } else {
        /* the inode lock is already held */
        /* It's OK to not use invalidator because it's in reverse order  */
        for (index = end_index; index >= start_index; index--) {
            addr = TRANS_OFS_TO_ADDR(sbi, linix_get(&sih->ix, index));
            linix_delete(&sih->ix, index, index, true);
            if (ENABLE_META_ASYNC(sb)) {
                hk_invalid_hdr_background(sb, inode, addr, index);
            } else {
                use_layout_for_addr(sb, addr);
                sm_invalid_hdr(sb, addr, sih->ino);
                unuse_layout_for_addr(sb, addr);
            }
            freed++;
        }
    }

    inode->i_blocks -= (freed * (1 << (data_bits -
                                       sb->s_blocksize_bits)));

    sih->i_blocks = inode->i_blocks;
}

static void hk_setsize(struct inode *inode, loff_t oldsize, loff_t newsize)
{
    struct super_block *sb = inode->i_sb;
    struct hk_inode_info_header *sih = HK_IH(inode);
    INIT_TIMING(setsize_time);

    /* We only support truncate regular file */
    if (!(S_ISREG(inode->i_mode))) {
        hk_err(inode->i_sb, "%s:wrong file mode %x\n", inode->i_mode);
        return;
    }

    HK_START_TIMING(setsize_t, setsize_time);

    inode_dio_wait(inode);

    hk_dbgv("%s: inode %lu, old size %llu, new size %llu\n",
            __func__, inode->i_ino, oldsize, newsize);

    if (newsize != oldsize) {
        hk_prepare_truncate(sb, inode, newsize);
        i_size_write(inode, newsize);
        sih->i_size = newsize;
    }

    /* FIXME: we should make sure that there is nobody reading the inode
     * before truncating it. Also we need to munmap the truncated range
     * from application address space, if mmapped.
     */
    /* synchronize_rcu(); */

    /* FIXME: Do we need to clear truncated DAX pages? */
    //	dax_truncate_page(inode, newsize, hk_dax_get_block);
    truncate_pagecache(inode, newsize);
    hk_truncate_file_blocks(inode, newsize, oldsize);
    HK_END_TIMING(setsize_t, setsize_time);
}

int hk_notify_change(struct dentry *dentry, struct iattr *attr)
{
    struct inode *inode = dentry->d_inode;
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    struct super_block *sb = inode->i_sb;
    int ret;
    unsigned int ia_valid = attr->ia_valid, attr_mask;
    loff_t oldsize = inode->i_size;
    INIT_TIMING(setattr_time);

    HK_START_TIMING(setattr_t, setattr_time);

    ret = setattr_prepare(dentry, attr);
    if (ret)
        goto out;

    /* Update inode with attr except for size */
    setattr_copy(inode, attr);

    attr_mask = ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_SIZE | ATTR_ATIME | ATTR_MTIME | ATTR_CTIME;

    ia_valid = ia_valid & attr_mask;

    if (ia_valid == 0)
        goto out;

    ret = hk_handle_setattr_operation(sb, inode, ia_valid, attr);
    if (ret)
        goto out;

    /* Only after setattr entry is committed, we can truncate size */
    if ((ia_valid & ATTR_SIZE) && (attr->ia_size != oldsize ||
                                   sih->i_flags & cpu_to_le32(HK_EOFBLOCKS_FL))) {
        hk_setsize(inode, oldsize, attr->ia_size);
    }

out:
    HK_END_TIMING(setattr_t, setattr_time);
    return ret;
}

struct inode *hk_iget_opened(struct super_block *sb, unsigned long ino)
{
    struct inode *inode;
    struct hk_inode_info *si;

    inode = iget_locked(sb, ino);

    if (unlikely(!inode)) {
        hk_err(sb, "%s: No memory\n", __func__);
        return ERR_PTR(-ENOMEM);
    }

    /* The inode is already exsited */
    if (!(inode->i_state & I_NEW)) {
        goto out;
    }

    si = HK_I(inode);
    hk_rebuild_inode(sb, si, ino, false);
    inode->i_ino = ino;

    /* The inode has't been load up, it's not opened */
    unlock_new_inode(inode);

    iput(inode);

    inode = NULL;
out:
    return inode;
}

struct inode *hk_iget(struct super_block *sb, unsigned long ino)
{
    struct hk_inode_info *si;
    struct inode *inode;
    unsigned long irq_flags = 0;
    int err;

    inode = iget_locked(sb, ino);
    if (unlikely(!inode)) {
        hk_err(sb, "%s: No memory\n", __func__);
        return ERR_PTR(-ENOMEM);
    }
    /* The inode is already exsited */
    if (!(inode->i_state & I_NEW))
        return inode;

    si = HK_I(inode);
    if (!si->header && !ENABLE_META_PACK(sb)) {
        BUG_ON(1);
    }

    hk_dbgv("%s: inode %lu\n", __func__, ino);

    if (ENABLE_META_PACK(sb)) {
        /* Do nothing */
    } else {
        struct hk_inode *pi;
        pi = hk_get_inode_by_ino(sb, ino);
        if (!pi) {
            hk_dbg("%s: failed to get inode %lu, only supports up to %lu\n",
                   __func__, ino, HK_NUM_INO - 1);
            err = -EACCES;
            goto fail;
        }
    }

    err = hk_rebuild_inode(sb, si, ino, true);
    if (err) {
        hk_dbg("%s: failed to rebuild inode %lu, ret %d\n", __func__, ino, err);
        goto fail;
    }

    err = hk_build_vfs_inode(sb, inode, ino);
    if (unlikely(err)) {
        hk_dbg("%s: failed to read inode %lu\n", __func__, ino);
        goto fail;
    }

    inode->i_ino = ino;

    unlock_new_inode(inode);
    return inode;
fail:
    iget_failed(inode);
    return ERR_PTR(err);
}

void *hk_inode_get_slot(struct hk_inode_info_header *sih, u64 offset)
{
    struct hk_inode_info *si = sih->si;
    BUG_ON(!si);
    struct super_block *sb = si->vfs_inode.i_sb;
    u32 ofs_blk = GET_ALIGNED_BLKNR(offset);

    if (ENABLE_META_PACK(sb)) {
        obj_ref_data_t *ref = NULL;
        u32 blk;

        ref = (obj_ref_data_t *)linix_get(&sih->ix, ofs_blk);
        if (!ref) {
            return NULL;
        }

        /* check if offset is in ref */
        if (offset >= ref->ofs && offset < ref->ofs + ((u64)ref->num << HUNTER_BLK_SHIFT)) {
            return ref;
        }

        hk_dbg("offset %lu (%lu) is not in ref [%lu, %lu] ([%lu, %lu]), inconsistency happened\n", offset, ofs_blk, ref->ofs, ref->ofs + ((u64)ref->num << HUNTER_BLK_SHIFT), GET_ALIGNED_BLKNR(ref->ofs), GET_ALIGNED_BLKNR(ref->ofs + ((u64)ref->num << HUNTER_BLK_SHIFT)));
        BUG_ON(1);
    } else {
        return (void *)linix_get(&sih->ix, ofs_blk);
    }

    return NULL;
}

const struct address_space_operations hk_aops_dax = {
    .writepages = NULL,
    .direct_IO = NULL,
    /*.dax_mem_protect	= hk_dax_mem_protect,*/
};
