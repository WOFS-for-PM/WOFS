/*
 * BRIEF DESCRIPTION
 *
 * WOFS Inode rebuild methods.
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

#include "wofs.h"

struct wofs_inode_rebuild {
    u64 i_size;
    u32 i_flags;       /* Inode flags */
    u32 i_ctime;       /* Inode modification time */
    u32 i_mtime;       /* Inode b-tree Modification time */
    u32 i_atime;       /* Access time */
    u32 i_uid;         /* Owner Uid */
    u32 i_gid;         /* Group Id */
    u32 i_generation;  /* File version (for NFS) */
    u16 i_links_count; /* Links count */
    u16 i_mode;        /* File mode */
    u64 i_num_entrys;  /* Number of entries in this inode */
    u64 tstamp;
};

static void wofs_update_inode_with_rebuild(struct super_block *sb, struct wofs_inode_rebuild *reb,
                                         struct wofs_inode *pi)
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

static int wofs_init_inode_rebuild(struct super_block *sb, struct wofs_inode_rebuild *reb,
                                 struct wofs_inode *pi)
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

static int wofs_guess_slots(struct super_block *sb)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    size_t avg_size;
    int slots;

    avg_size = wofs_dw_stat_avg(&sbi->dw);
    slots = avg_size / WOFS_LBLK_SZ(sbi) == 0 ? 1 : avg_size / WOFS_LBLK_SZ(sbi);
    return slots;
}

void wofs_init_header(struct super_block *sb, struct wofs_inode_info_header *sih,
                    u16 i_mode)
{
    int slots = WOFS_LINIX_SLOTS;

    sih->i_size = 0;
    sih->ino = 0;
    sih->i_blocks = 0;
    sih->norm_spec.pi_addr = 0;
    sih->last_end = 0;

    if (S_ISPSEUDO(i_mode)) {
        linix_init(&sih->ix, 0);
    } else if (!S_ISLNK(i_mode)) {
        if (ENABLE_HISTORY_W(sb)) {
            slots = wofs_guess_slots(sb);
        }
        linix_init(&sih->ix, slots);
    } else { /* symlink only need one block */
        linix_init(&sih->ix, 1);
    }

    hash_init(sih->dirs);
    sih->i_num_dentrys = 0;

    sih->vma_tree = RB_ROOT;
    sih->num_vmas = 0;
    INIT_LIST_HEAD(&sih->list);

    sih->i_mode = i_mode;
    sih->i_flags = 0;

    sih->pack_spec.latest_fop.latest_attr = NULL;
    sih->pack_spec.latest_fop.latest_inode = NULL;
    sih->pack_spec.latest_fop.latest_inline_attr = 0;
    
    sih->si = NULL;

    return 0;
}

static int wofs_rebuild_dir_table_for_blk(struct super_block *sb, u64 f_blk, struct wofs_inode_info_header *sih,
                                        struct wofs_inode_rebuild *reb)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_dentry *direntry;
    u16 i;
    u64 blk_addr;
    for (i = 0; i < MAX_DENTRY_PER_BLK; i++) {
        blk_addr = TRANS_OFS_TO_ADDR(sbi, linix_get(&sih->ix, f_blk));
        direntry = wofs_dentry_by_ix_from_blk(blk_addr, i);
        if (direntry->valid) {
            reb->i_num_entrys += 1;
            wofs_insert_dir_table(sb, sih, direntry->name, direntry->name_len, direntry);
        }
    }
}

extern void *wofs_lookup_d_obj_ref_lists(d_root_t *root, u32 ino, u8 type);

static int wofs_rebuild_data(struct wofs_sb_info *sbi, struct wofs_inode_info_header *sih, u32 ino)
{
    obj_mgr_t *obj_mgr = sbi->pack_layout.obj_mgr;
    d_root_t *root;
    d_obj_ref_list_t *data_list;
    struct list_head *pos;
    obj_ref_data_t *ref;
    data_update_t data_update;
    struct super_block *sb = sbi->sb;
    int i;
    int ret = 0;

    WOFS_ASSERT(S_ISREG(sih->i_mode));

    if (!sih->ix.slots) {
        ret = linix_init(&sih->ix, WOFS_LINIX_SLOTS); 
        if (ret) {
            wofs_err(sb, "Init inode data index failed\n");
            return ret;
        }
    } else {
        /* opened already */
        goto out;
    }

    for (i = 0; i < obj_mgr->num_d_roots; i++) {
        root = &obj_mgr->d_roots[i];
        use_droot(root, data);
        data_list = wofs_lookup_d_obj_ref_lists(root, ino, OBJ_DATA);
        if (data_list) {
            list_for_each(pos, &data_list->list) {
                ref = list_entry(pos, obj_ref_data_t, node);

                data_update.build_from_exist = true;
                data_update.exist_ref = ref;
                data_update.addr = ref->hdr.addr;
                data_update.blk = get_pm_blk(sbi, ref->data_offset);
                data_update.ofs = ref->ofs;
                data_update.num = ref->num;
                data_update.i_cmtime = sih->i_mtime;
                data_update.i_size = sih->i_size;

                ur_dram_data(obj_mgr, sih, &data_update);
            }
        }
        rls_droot(root, data);
    }

out:
    return ret;
}

int wofs_rebuild_dirs(struct wofs_sb_info *sbi, struct wofs_inode_info_header *sih, u32 ino)
{
    obj_mgr_t *obj_mgr = sbi->pack_layout.obj_mgr;
    d_root_t *root;
    d_obj_ref_list_t *dentry_list;
    struct list_head *pos;
    struct wofs_obj_dentry *obj_dentry;
    obj_ref_dentry_t *ref;
    struct super_block *sb = sbi->sb;
    int i, ret = 0;

    WOFS_ASSERT(S_ISDIR(sih->i_mode));
    
    /* TODO: check opened ? */

    for (i = 0; i < obj_mgr->num_d_roots; i++) {
        root = &obj_mgr->d_roots[i];
        use_droot(root, dentry);
        dentry_list = wofs_lookup_d_obj_ref_lists(root, ino, OBJ_DENTRY);
        if (dentry_list) {
            list_for_each(pos, &dentry_list->list) {
                ref = list_entry(pos, obj_ref_dentry_t, node);
                obj_dentry = get_pm_addr(sbi, ref->hdr.addr);
                if (ref->target_ino == ino && ino == WOFS_ROOT_INO) /* root */
                    continue;
                ret = wofs_insert_dir_table(sb, sih, obj_dentry->name, strlen(obj_dentry->name), ref);
                if (ret) {
                    wofs_err(sb, "insert ref %p into dir table failed, ret %d\n", ref, ret);
                    return ret;
                }
            }
        }
        rls_droot(root, dentry);
    }

out:
    return ret;
}

static int wofs_rebuild_inode_blks(struct super_block *sb, struct wofs_inode *pi,
                                 struct wofs_inode_info_header *sih)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_inode_rebuild rebuild, *reb;
    u64 ino = sih->ino;
    u64 addr;

    INIT_TIMING(rebuild_time);
    int ret;

    WOFS_START_TIMING(rebuild_blks_t, rebuild_time);
    wofs_dbg_verbose("Rebuild file inode %llu tree\n", ino);
    
    switch (__le16_to_cpu(sih->i_mode) & S_IFMT) {
    case S_IFLNK:
    case S_IFREG:
        ret = wofs_rebuild_data(sbi, sih, ino);
        break;
    case S_IFDIR:
        ret = wofs_rebuild_dirs(sbi, sih, ino);
        break;
    default:
        break;
    }

    sih->i_blocks = sih->i_size / WOFS_LBLK_SZ(sbi);

out:
    WOFS_END_TIMING(rebuild_blks_t, rebuild_time);
    return ret;
}

int wofs_check_inode(struct super_block *sb, u64 ino)
{
    int ret;
    struct wofs_inode *pi;

    // TODO: Check Inode Integrity
    pi = wofs_get_inode_by_ino(sb, ino);
    ret = pi->valid == 1 ? 0 : -ESTALE;

    return ret;
}

/* initialize wofs inode header and other DRAM data structures */
int wofs_rebuild_inode(struct super_block *sb, struct wofs_inode_info *si, u32 ino, bool build_blks)
{
    struct wofs_inode_info_header *sih = si->header;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_inode *pi = NULL;
    unsigned long irq_flags = 0;
    int ret = 0;

    BUG_ON(sih);
    sih = obj_mgr_get_imap_inode(sbi->pack_layout.obj_mgr, ino);
    if (!sih) {
        return -ENOENT;
    }
    si->header = sih;
    pi = NULL;

    sih->ino = ino;
    if (build_blks)
        ret = wofs_rebuild_inode_blks(sb, pi, sih);

    return ret;
}
