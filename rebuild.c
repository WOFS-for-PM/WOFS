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

struct hk_inode_rebuild {
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

static void hk_update_inode_with_rebuild(struct super_block *sb, struct hk_inode_rebuild *reb,
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
    int slots;

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
    sih->norm_spec.pi_addr = 0;
    sih->last_end = 0;

    if (S_ISPSEUDO(i_mode)) {
        linix_init(&sih->ix, 0);
    } else if (!S_ISLNK(i_mode)) {
        if (ENABLE_HISTORY_W(sb)) {
            slots = hk_guess_slots(sb);
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

    if (ENABLE_META_PACK(sb)) {
        sih->pack_spec.latest_fop.latest_attr = NULL;
        sih->pack_spec.latest_fop.latest_inode = NULL;
        sih->pack_spec.latest_fop.latest_inline_attr = 0;
    } else {
        sih->norm_spec.tstamp = 0;
        sih->norm_spec.h_addr = 0;
    }

    sih->si = NULL;

    return 0;
}

static int hk_rebuild_dir_table_for_blk(struct super_block *sb, u64 f_blk, struct hk_inode_info_header *sih,
                                        struct hk_inode_rebuild *reb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_dentry *direntry;
    u16 i;
    u64 blk_addr;
    for (i = 0; i < MAX_DENTRY_PER_BLK; i++) {
        blk_addr = TRANS_OFS_TO_ADDR(sbi, linix_get(&sih->ix, f_blk));
        direntry = hk_dentry_by_ix_from_blk(blk_addr, i);
        if (direntry->valid) {
            reb->i_num_entrys += 1;
            hk_insert_dir_table(sb, sih, direntry->name, direntry->name_len, direntry);
        }
    }
}

extern void *hk_lookup_d_obj_ref_lists(d_root_t *root, u32 ino, u8 type);

static int hk_rebuild_data(struct hk_sb_info *sbi, struct hk_inode_info_header *sih, u32 ino)
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

    HK_ASSERT(S_ISREG(sih->i_mode));

    if (!sih->ix.slots) {
        ret = linix_init(&sih->ix, HK_LINIX_SLOTS); 
        if (ret) {
            hk_err(sb, "Init inode data index failed\n");
            return ret;
        }
    } else {
        /* opened already */
        goto out;
    }

    for (i = 0; i < obj_mgr->num_d_roots; i++) {
        root = &obj_mgr->d_roots[i];
        use_droot(root, data);
        data_list = hk_lookup_d_obj_ref_lists(root, ino, OBJ_DATA);
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

int hk_rebuild_dirs(struct hk_sb_info *sbi, struct hk_inode_info_header *sih, u32 ino)
{
    obj_mgr_t *obj_mgr = sbi->pack_layout.obj_mgr;
    d_root_t *root;
    d_obj_ref_list_t *dentry_list;
    struct list_head *pos;
    struct hk_obj_dentry *obj_dentry;
    obj_ref_dentry_t *ref;
    struct super_block *sb = sbi->sb;
    int i, ret = 0;

    HK_ASSERT(S_ISDIR(sih->i_mode));
    
    /* TODO: check opened ? */

    for (i = 0; i < obj_mgr->num_d_roots; i++) {
        root = &obj_mgr->d_roots[i];
        use_droot(root, dentry);
        dentry_list = hk_lookup_d_obj_ref_lists(root, ino, OBJ_DENTRY);
        if (dentry_list) {
            list_for_each(pos, &dentry_list->list) {
                ref = list_entry(pos, obj_ref_dentry_t, node);
                obj_dentry = get_pm_addr(sbi, ref->hdr.addr);
                if (ref->target_ino == ino && ino == HUNTER_ROOT_INO) /* root */
                    continue;
                ret = hk_insert_dir_table(sb, sih, obj_dentry->name, strlen(obj_dentry->name), ref);
                if (ret) {
                    hk_err(sb, "insert ref %p into dir table failed, ret %d\n", ref, ret);
                    return ret;
                }
            }
        }
        rls_droot(root, dentry);
    }

out:
    return ret;
}

static int hk_rebuild_inode_blks(struct super_block *sb, struct hk_inode *pi,
                                 struct hk_inode_info_header *sih)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_rebuild rebuild, *reb;
    u64 ino = sih->ino;
    u64 addr;

    INIT_TIMING(rebuild_time);
    int ret;

    HK_START_TIMING(rebuild_blks_t, rebuild_time);
    hk_dbg_verbose("Rebuild file inode %llu tree\n", ino);
    
    if (ENABLE_META_PACK(sb)) {
        switch (__le16_to_cpu(sih->i_mode) & S_IFMT) {
        case S_IFLNK:
        case S_IFREG:
            ret = hk_rebuild_data(sbi, sih, ino);
            break;
        case S_IFDIR:
            ret = hk_rebuild_dirs(sbi, sih, ino);
            break;
        default:
            break;
        }
    } else {
        struct hk_header *hdr;
        struct hk_header *conflict_hdr;
        unsigned long irq_flags = 0;

        reb = &rebuild;
        sih->norm_spec.h_addr = le64_to_cpu(pi->h_addr);

        ret = hk_init_inode_rebuild(sb, reb, pi);
        if (ret)
            return ret;

        sih->norm_spec.pi_addr = (u64)pi;

        hk_dbg_verbose("Blk Summary head 0x%llx\n",
                    sih->norm_spec.h_addr);

        if (ret)
            goto out;

        traverse_inode_hdr(sbi, pi, hdr)
        {
            /* Hdr Conflict */
            if (hdr->f_blk < sih->ix.num_slots && linix_get(&sih->ix, hdr->f_blk) != 0) {
                conflict_hdr = sm_get_hdr_by_addr(sb, TRANS_OFS_TO_ADDR(sbi, linix_get(&sih->ix, hdr->f_blk)));
                if (hdr->tstamp >= conflict_hdr->tstamp) { /* Insert New, Evict Old */
                    addr = sm_get_addr_by_hdr(sb, conflict_hdr);

                    use_layout_for_addr(sb, addr);
                    sm_invalid_hdr(sb, addr, conflict_hdr->ino);
                    unuse_layout_for_addr(sb, addr);

                    linix_insert(&sih->ix, hdr->f_blk, TRANS_ADDR_TO_OFS(sbi, sm_get_addr_by_hdr(sb, hdr)), true);
                } else { /* Not Insert */
                    addr = sm_get_addr_by_hdr(sb, hdr);

                    use_layout_for_addr(sb, addr);
                    sm_invalid_hdr(sb, addr, hdr->ino);
                    unuse_layout_for_addr(sb, addr);
                }
            } else {
                linix_insert(&sih->ix, hdr->f_blk, TRANS_ADDR_TO_OFS(sbi, sm_get_addr_by_hdr(sb, hdr)), true);
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

        sih->i_size = le64_to_cpu(reb->i_size);
        sih->i_mode = le64_to_cpu(reb->i_mode);
        sih->i_flags = le32_to_cpu(reb->i_flags);
        sih->i_num_dentrys = le64_to_cpu(reb->i_num_entrys);
        sih->norm_spec.tstamp = reb->tstamp;

        hk_memunlock_inode(sb, pi, &irq_flags);
        hk_update_inode_with_rebuild(sb, reb, pi);
        hk_memlock_inode(sb, pi, &irq_flags);

        hk_flush_buffer(pi, sizeof(struct hk_inode), true);
    }
    sih->i_blocks = sih->i_size / HK_LBLK_SZ(sbi);

out:
    HK_END_TIMING(rebuild_blks_t, rebuild_time);
    return ret;
}

int hk_check_inode(struct super_block *sb, u64 ino)
{
    int ret;
    struct hk_inode *pi;

    // TODO: Check Inode Integrity
    pi = hk_get_inode_by_ino(sb, ino);
    ret = pi->valid == 1 ? 0 : -ESTALE;

    return ret;
}

/* initialize hunter inode header and other DRAM data structures */
int hk_rebuild_inode(struct super_block *sb, struct hk_inode_info *si, u32 ino, bool build_blks)
{
    struct hk_inode_info_header *sih = si->header;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode *pi = NULL;
    unsigned long irq_flags = 0;
    int ret = 0;

    if (ENABLE_META_PACK(sb)) {
		BUG_ON(sih);
        sih = obj_mgr_get_imap_inode(sbi->pack_layout.obj_mgr, ino);
        if (!sih) {
            return -ENOENT;
        }
        si->header = sih;
        pi = NULL;
    } else {
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
        sih->norm_spec.pi_addr = (u64)pi;

        if (pi->valid == 0) {
            hk_dbg("%s: inode %llu is invalid or deleted.\n", __func__, ino);
            return -ESTALE;
        }

        hk_dbgv("%s: inode %llu, addr 0x%llx, valid %d, head 0x%llx\n",
                __func__, ino, sih->norm_spec.pi_addr, pi->valid, pi->h_addr);
    }

    sih->ino = ino;
    if (build_blks)
        ret = hk_rebuild_inode_blks(sb, pi, sih);

    return ret;
}
