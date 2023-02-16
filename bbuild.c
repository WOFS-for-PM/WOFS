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


int hk_test_bit(u32 bit, u8 *bm)
{
    u32 byte = bit >> 3;
    u32 bit_in_byte = bit & 0x7;
    return (bm[byte] >> bit_in_byte) & 0x1;
}

void hk_set_bit(u32 bit, u8 *bm)
{
    u32 byte = bit >> 3;
    u32 bit_in_byte = bit & 0x7;
    bm[byte] |= (1 << bit_in_byte);
}

void hk_clear_bit(u32 bit, u8 *bm)
{
    u32 byte = bit >> 3;
    u32 bit_in_byte = bit & 0x7;
    bm[byte] &= ~(1 << bit_in_byte);
}

#define BMBLK_ATTR      0
#define BMBLK_UNLINK    1
#define BMBLK_CREATE    2
#define BMBLK_DATA      3
#define BMBLK_NUM       (4)
#define BMBLK_SIZE(sbi) (sbi->tl_per_type_bm_reserved_blks << PAGE_SHIFT)

#define HK_BM_ADDR(sbi, bmblk_type) \
    (u8 *)((u64)sbi->bm_start + (bmblk_type * (sbi->tl_per_type_bm_reserved_blks << HUNTER_BLK_SHIFT)))

u8 *in_dram_bm_buf = NULL;
u8 *in_dram_blk_buf = NULL;

#define hk_traverse_bm(sbi, bm, pointed_blk) \
    for (pointed_blk = 0; pointed_blk < ((sbi->tl_per_type_bm_reserved_blks << HUNTER_BLK_SHIFT) << 3); pointed_blk++)

struct basic_list_node {
    struct list_head node;
    u64 value;
};

static struct basic_list_node *create_basic_list_node(u64 value)
{
    struct basic_list_node *node = kzalloc(sizeof(struct basic_list_node), GFP_KERNEL);
    if (!node)
        return NULL;

    node->value = value;

    return node;
}

static void free_basic_list_node(struct basic_list_node *node)
{   
    if (node)
        kfree(node);
}

static int hk_create_dram_bufs(struct hk_sb_info *sbi)
{
    struct super_block *sb = sbi->sb;
    in_dram_bm_buf = kzalloc(BMBLK_SIZE(sbi), GFP_KERNEL);
    if (!in_dram_bm_buf) {
        hk_err(sb, "failed to allocate in_dram_bm_buf");
        return -ENOMEM;
    }

    in_dram_blk_buf = kzalloc(BMBLK_SIZE(sbi), GFP_KERNEL);
    if (!in_dram_blk_buf) {
        hk_err(sb, "failed to allocate in_dram_blk_buf");
        kfree(in_dram_bm_buf);
        return -ENOMEM;
    }

    return 0;
}

static void hk_destroy_dram_bufs(void)
{
    if (in_dram_bm_buf)
        kfree(in_dram_bm_buf);
    if (in_dram_blk_buf)
        kfree(in_dram_blk_buf);
}

/* Recovery Routines for Pack Layout */
static inline u8 *__hk_get_bm_addr(struct hk_sb_info *sbi, void *buf, u32 bmblk)
{
    u8 *bm;
    if (buf) {
        memcpy(buf, HK_BM_ADDR(sbi, bmblk), BMBLK_SIZE(sbi));
        bm = buf;
    } else {
        bm = HK_BM_ADDR(sbi, bmblk);
    }
    return bm;
}

static inline u8 *__hk_get_blk_addr(struct hk_sb_info *sbi, void *buf, u32 blk)
{
    u8 *addr;
    if (buf) {
        memcpy(buf, get_pm_blk_addr(sbi, blk), HK_PBLK_SZ(sbi));
        addr = buf;
    } else {
        addr = get_pm_blk_addr(sbi, blk);
    }
    return addr;
}

int hk_recovery_data_pkgs(struct hk_sb_info *sbi, u8 *bm_buf, u8 *blk_buf, u64 *max_vtail)
{
    u8 *data_bm;
    u8 *cur_data;
    u8 *start_addr;
    struct hk_inode *inode;
    struct hk_obj_data *data;
    obj_ref_data_t *ref_data;
    u64 in_pm_addr;
    tlrestore_param_t param;
    u32 blk;
    struct hk_obj_hdr *hdr = NULL;

    data_bm = __hk_get_bm_addr(sbi, bm_buf, BMBLK_DATA);
    hk_traverse_bm(sbi, data_bm, blk)
    {
        cur_data = __hk_get_blk_addr(sbi, blk_buf, blk);
        in_pm_addr = get_pm_blk_addr(sbi, blk);
        start_addr = cur_data;
        while (cur_data < start_addr + HK_PBLK_SZ(sbi)) {
            get_pkg_hdr(cur_data, PKG_DATA, (u64 *)&hdr);
            if (check_pkg_valid(cur_data, OBJ_DATA_SIZE, hdr) == 0) {
                data = (struct hk_obj_data *)cur_data;
                tl_build_restore_param(&param, blk, 1, TL_BLK);
                tlrestore(get_tl_allocator(sbi, get_pm_offset(sbi, in_pm_addr)), &param);
                ref_data = ref_data_create(get_pm_offset(sbi, in_pm_addr), data->ino, data->ofs, data->num, get_pm_blk_addr(sbi, data->blk));
                obj_mgr_load_dobj_control(sbi->obj_mgr, ref_data, OBJ_DATA);
                if (data->hdr.vtail > *max_vtail)
                    *max_vtail = data->hdr.vtail;
            }
            cur_data += OBJ_DATA_SIZE;
            in_pm_addr += OBJ_DATA_SIZE;
        }
    }

    return 0;
}

int __check_should_update_attr(struct hk_sb_info *sbi, struct hk_inode_info_header *sih, struct hk_obj_attr *attr)
{
    struct hk_obj_attr *orig_attr = get_pm_addr(sbi, sih->latest_fop.latest_attr->hdr.addr);
    if (orig_attr->hdr.vtail < attr->hdr.vtail) {
        return 1;
    }
    return 0;
}

void __hk_build_attr_update_from_pm(struct hk_sb_info *sbi, struct hk_obj_attr *attr, attr_update_t *attr_update)
{
    attr_update->addr = get_pm_offset(sbi, get_pm_offset(sbi, (u64)attr));
    attr_update->from_pkg = PKG_CREATE;
    attr_update->dep_addr = 0;
    attr_update->i_atime = attr->i_atime;
    attr_update->i_mtime = attr->i_mtime;
    attr_update->i_ctime = attr->i_ctime;
    attr_update->i_size = attr->i_size;
    attr_update->i_gid = attr->i_gid;
    attr_update->i_uid = attr->i_uid;
    attr_update->i_mode = attr->i_mode;
    attr_update->i_links_count = attr->i_links_count;
}

void __hk_build_inode_update_from_pm(struct hk_sb_info *sbi, struct hk_obj_inode *inode, inode_update_t *inode_update)
{
    inode_update->addr = get_pm_offset(sbi, (u64)inode);
    inode_update->ino = inode->ino;
}

int hk_recovery_create_pkgs(struct hk_sb_info *sbi, u8 *bm_buf, u8 *blk_buf, u64 *max_vtail)
{
    int ret = 0;
    u8 *create_bm;
    u8 *cur_create;
    u8 *cur_addr;
    u8 *start_addr;
    u64 in_pm_addr;
    struct super_block *sb = sbi->sb;
    struct hk_inode_info_header *sih;
    struct basic_list_node *lnode;
    struct hk_obj_inode *obj_inode;
    struct hk_obj_dentry *obj_dentry;
    struct hk_obj_attr *attr, *pattr;
    obj_ref_dentry_t *ref_dentry;
    tlrestore_param_t param;
    struct hk_pkg_hdr *pkg_hdr;
    attr_update_t attr_update;
    inode_update_t inode_update;
    struct list_head attr_list, *pos, *n;
    u64 entrynr;
    u32 num;
    u32 blk;

    INIT_LIST_HEAD(&attr_list);

    create_bm = __hk_get_bm_addr(sbi, bm_buf, BMBLK_CREATE);
    hk_traverse_bm(sbi, create_bm, blk)
    {
        cur_create = __hk_get_blk_addr(sbi, blk_buf, blk);
        in_pm_addr = get_pm_blk_addr(sbi, blk);
        start_addr = cur_create;
        while (cur_create < start_addr + HK_PBLK_SZ(sbi)) {
            get_pkg_hdr(cur_create, PKG_CREATE, (u64 *)&pkg_hdr);
            if (check_pkg_valid(cur_create, MTA_PKG_CREATE_SIZE, &pkg_hdr->hdr) == 0) {
                cur_addr = cur_create;
                entrynr = GET_ENTRYNR(get_pm_offset(sbi, in_pm_addr));
                num = MTA_PKG_CREATE_BLK;
                tl_build_restore_param(&param, blk, (entrynr << 32 | num), TL_MTA | TL_MTA_PKG_CREATE);
                tlrestore(get_tl_allocator(sbi, get_pm_offset(sbi, in_pm_addr)), &param);

                /* control inode */
                obj_inode = (struct hk_obj_inode *)cur_create;
                sih = hk_alloc_hk_inode_info_header();
                if (!sih) {
                    ret = -ENOMEM;
                    hk_err(sb, "Create inode failed\n");
                    goto out;
                }
                __hk_build_inode_update_from_pm(sbi, obj_inode, &inode_update);
                ur_dram_latest_inode(sbi->obj_mgr, sih, &inode_update);
                obj_mgr_load_imap_control(sbi->obj_mgr, sih);
                cur_addr += OBJ_INODE_SIZE;

                /* pend addr */
                attr = (struct hk_obj_attr *)cur_create;
                lnode = create_basic_list_node(attr);
                list_add_tail(&lnode->node, &attr_list);
                cur_addr += OBJ_ATTR_SIZE;

                /* pend pattr */
                pattr = (struct hk_obj_attr *)cur_create;
                lnode = create_basic_list_node(pattr);
                list_add_tail(&lnode->node, &attr_list);
                cur_addr += OBJ_ATTR_SIZE;

                /* control dentry */
                obj_dentry = (struct hk_obj_dentry *)cur_create;
                ref_dentry = ref_dentry_create(get_pm_offset(sbi, in_pm_addr + OBJ_INODE_SIZE + 2 * OBJ_ATTR_SIZE), obj_dentry->name, strlen(obj_dentry->name), obj_inode->ino, obj_dentry->parent_ino);
                obj_mgr_load_dobj_control(sbi->obj_mgr, ref_dentry, OBJ_DENTRY);

                if (pkg_hdr->hdr.vtail > *max_vtail)
                    *max_vtail = pkg_hdr->hdr.vtail;
            }

            cur_create += MTA_PKG_CREATE_SIZE;
            in_pm_addr += MTA_PKG_CREATE_SIZE;
        }
    }

    /* control attr */
    list_for_each_safe(pos, n, &attr_list) {
        lnode = list_entry(pos, struct basic_list_node, node);
        attr = (struct hk_obj_attr *)lnode->value;
        sih = obj_mgr_get_imap_inode(sbi->obj_mgr, attr->ino);
        if (!sih) {
            hk_warn("Can't find inode %lu in imap\n", attr->ino);
        } else {
            if (__check_should_update_attr(sbi, sih, attr)) {
                __hk_build_attr_update_from_pm(sbi, attr, &attr_update);
                ur_dram_latest_attr(sbi->obj_mgr, obj_mgr_get_imap_inode(sbi->obj_mgr, attr->ino), &attr_update);
            }
        }
        list_del(pos);
        free_basic_list_node(lnode);
    }

out:
    return ret;
}

int hk_recovery_unlink_pkgs(struct hk_sb_info *sbi, u8 *bm_buf, u8 *blk_buf, u64 *max_vtail)
{
    int ret = 0;
    u8 *unlink_bm;
    u8 *cur_unlink;
    u8 *cur_addr;
    u8 *start_addr;
    u64 in_pm_addr;
    struct hk_inode_info_header *sih, *psih;
    struct hk_pkg_hdr *pkg_hdr;
    struct hk_obj_attr *pattr;
    obj_ref_dentry_t *ref_dentry;
    attr_update_t pattr_update;
    tlrestore_param_t param;
    d_obj_ref_list_t *dentry_list;
    struct list_head *pos;
    u64 entrynr;
    u32 num;
    u32 blk;
    u32 pino;

    /* check and clean all unlink pkg */
    unlink_bm = __hk_get_bm_addr(sbi, bm_buf, BMBLK_UNLINK);
    hk_traverse_bm(sbi, unlink_bm, blk)
    {
        cur_unlink = __hk_get_blk_addr(sbi, blk_buf, blk);
        in_pm_addr = get_pm_blk_addr(sbi, blk);
        start_addr = cur_unlink;
        while (cur_unlink < start_addr + HK_PBLK_SZ(sbi)) {
            get_pkg_hdr(cur_unlink, PKG_UNLINK, (u64 *)&pkg_hdr);
            if (check_pkg_valid(cur_unlink, MTA_PKG_UNLINK_SIZE, &pkg_hdr->hdr) == 0) {
                cur_addr = cur_unlink;
                /* parse parent attr */
                pattr = (struct hk_obj_attr *)cur_addr;
                psih = obj_mgr_get_imap_inode(sbi->obj_mgr, pattr->ino);
                if (!psih) {
                    hk_warn("Can't find parent inode %lu in imap\n", pattr->ino);
                    continue;
                }
                cur_addr += OBJ_ATTR_SIZE;
                /* parse pkg hdr */
                pkg_hdr = (struct hk_pkg_hdr *)cur_addr;
                sih = obj_mgr_get_imap_inode(sbi->obj_mgr, pkg_hdr->unlink_hdr.unlinked_ino);

                if (!__check_should_update_attr(sbi, psih, pattr)) {
                    hk_warn("Parent inode %lu should be updated since UNLINK is always after CREATE\n", pattr->ino);
                    continue;
                }

                __hk_build_attr_update_from_pm(sbi, pattr, &pattr_update);
                pattr_update.from_pkg = PKG_UNLINK;
                pattr_update.dep_addr = sih->latest_fop.latest_inode->hdr.addr;
                ur_dram_latest_attr(sbi->obj_mgr, psih, &pattr_update);
                if (sih) {
                    hk_warn("Inode %lu is unlinked, but found in imap, which means corresponding CREATE pkg is not used\n", sih->ino);
                    obj_mgr_unload_imap_control(sbi->obj_mgr, sih);
                    obj_mgr_get_dobjs(sbi->obj_mgr, pattr->ino, OBJ_DENTRY, (void *)&dentry_list);
                    list_for_each(pos, &dentry_list->list) {
                        ref_dentry = container_of(pos, obj_ref_dentry_t, node);
                        if (ref_dentry->target_ino == sih->ino) {
                            reclaim_dram_create(sbi->obj_mgr, sih, ref_dentry);
                            break;
                        }
                    }
                }
                entrynr = GET_ENTRYNR(get_pm_offset(sbi, in_pm_addr));
                num = MTA_PKG_CREATE_BLK;
                tl_build_restore_param(&param, blk, (entrynr << 32 | num), TL_MTA | TL_MTA_PKG_UNLINK);
                tlrestore(get_tl_allocator(sbi, get_pm_offset(sbi, in_pm_addr)), &param);

                if (pkg_hdr->hdr.vtail > *max_vtail)
                    *max_vtail = pkg_hdr->hdr.vtail;
            }
            cur_unlink += MTA_PKG_UNLINK_SIZE;
            in_pm_addr += MTA_PKG_UNLINK_SIZE;
        }
    }

out:
    return ret;
}

int hk_recovery_attr_pkgs(struct hk_sb_info *sbi, u8 *bm_buf, u8 *blk_buf, u64 *max_vtail)
{
    int ret = 0;
    u8 *attr_bm;
    u8 *cur_attr;
    u8 *start_addr;
    u64 in_pm_addr;
    struct hk_inode_info_header *sih;
    struct hk_obj_hdr *hdr;
    struct hk_obj_attr *attr;
    attr_update_t attr_update;
    tlrestore_param_t param;
    u64 entrynr;
    u32 num;
    u32 blk;
    u32 layout_idx;
    struct hk_layout_info *layout;

    /* check and clean all attr pkg */
    attr_bm = __hk_get_bm_addr(sbi, bm_buf, BMBLK_ATTR);
    hk_traverse_bm(sbi, attr_bm, blk)
    {
        cur_attr = __hk_get_blk_addr(sbi, blk_buf, blk);
        in_pm_addr = get_pm_blk_addr(sbi, blk);
        start_addr = cur_attr;
        while (cur_attr < start_addr + HK_PBLK_SZ(sbi)) {
            get_pkg_hdr(cur_attr, PKG_ATTR, (u64 *)&hdr);
            if (check_pkg_valid(cur_attr, MTA_PKG_ATTR_SIZE, hdr) == 0) {
                /* parse attr */
                attr = (struct hk_obj_attr *)cur_attr;
                sih = obj_mgr_get_imap_inode(sbi->obj_mgr, attr->ino);

                if (!sih) {
                    hk_warn("Can't find inode %lu in imap\n", attr->ino);
                    continue;
                }

                if (__check_should_update_attr(sbi, sih, attr)) {
                    entrynr = GET_ENTRYNR(get_pm_offset(sbi, in_pm_addr));
                    num = MTA_PKG_ATTR_BLK;
                    tl_build_restore_param(&param, blk, (entrynr << 32 | num), TL_MTA | TL_MTA_PKG_ATTR);
                    tlrestore(get_tl_allocator(sbi, get_pm_offset(sbi, in_pm_addr)), &param);

                    __hk_build_attr_update_from_pm(sbi, attr, &attr_update);
                    ur_dram_latest_attr(sbi->obj_mgr, sih, &attr_update);
                }

                if (attr->hdr.vtail > *max_vtail)
                    *max_vtail = attr->hdr.vtail;
            }
            cur_attr += MTA_PKG_ATTR_SIZE;
            in_pm_addr += MTA_PKG_ATTR_SIZE;
        }
    }

out:
    return ret;
}

unsigned long hk_get_bm_size(struct super_block *sb)
{
    if (ENABLE_META_PACK(sb)) {
        return BMBLK_SIZE(HK_SB(sb)) * BMBLK_NUM;
    } else {
        hk_warn("meta pack is disabled, no need to allocate bitmap");
        return 0;
    }
}

void hk_dump_bm(struct hk_sb_info *sbi, u16 bmblk)
{
    struct hk_layout_info *layout;
    tl_allocator_t *allocator;
    meta_mgr_t *meta_mgr;
    typed_meta_mgr_t *tmeta_mgr;
    u16 m_alloc_type = TL_MTA_TYPE_NUM;
    tl_node_t *cur;
    u8 *bm;
    int i, bkt;

    switch (bmblk)
    {
    case BMBLK_ATTR:
        m_alloc_type = TL_MTA_PKG_ATTR;
        break;
    case BMBLK_DATA:
        m_alloc_type = TL_MTA_PKG_DATA;
        break;
    case BMBLK_CREATE:
        m_alloc_type = TL_MTA_PKG_CREATE;
        break;
    case BMBLK_UNLINK:
        m_alloc_type = TL_MTA_PKG_UNLINK;
        break;
    default:
        break;
    }

    bm = __hk_get_bm_addr(sbi, NULL, bmblk);
    hk_info("%s: bmblk %d, bm @ 0x%llx\n", __func__, bmblk, bm);

    for (i = 0; i < sbi->num_layout; i++) {
        layout = &sbi->layouts[i];
        allocator = &layout->allocator;
        meta_mgr = &allocator->meta_manager;
        tmeta_mgr = &meta_mgr->tmeta_mgrs[meta_type_to_idx(m_alloc_type)];

        hash_for_each(tmeta_mgr->used_blks, bkt, cur, hnode) {
            hk_set_bit(cur->blk, bm);
        }
    }   
}

int hk_save_layouts(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_super_block *hk_sb = sbi->hk_sb;
    struct hk_layout_info *layout;
    struct hk_normal_data *nd;
    struct hk_pack_data *pd;
    int ret = 0;
    int cpuid;

    if (ENABLE_META_PACK(sb)) {
        pd = (struct hk_pack_data *)(hk_sb + sizeof(struct hk_super_block));
        pd->s_vtail = cpu_to_le64(atomic64_read(&sbi->vtail));
        hk_dump_bm(sbi, BMBLK_ATTR);
        hk_dump_bm(sbi, BMBLK_UNLINK);
        hk_dump_bm(sbi, BMBLK_CREATE);
        hk_dump_bm(sbi, BMBLK_DATA);
    } else {
        for (cpuid = 0; cpuid < sbi->num_layout; cpuid++) {
            layout = &sbi->layouts[cpuid];

            if (layout->ind.prep_blks != 0) {
                hk_dump_layout_info(layout);
            }
            nd = (struct hk_normal_data *)(hk_sb + sizeof(struct hk_super_block));
            nd->s_layout->s_atomic_counter = cpu_to_le64(layout->atomic_counter);
            nd->s_layout->s_ind.free_blks = cpu_to_le64(layout->ind.free_blks);
            nd->s_layout->s_ind.invalid_blks = cpu_to_le64(layout->ind.invalid_blks);
            nd->s_layout->s_ind.prep_blks = cpu_to_le64(layout->ind.prep_blks);
            HK_ASSERT(nd->s_layout->s_ind.prep_blks == 0);
            nd->s_layout->s_ind.valid_blks = cpu_to_le64(layout->ind.valid_blks);
            nd->s_layout->s_ind.total_blks = cpu_to_le64(layout->ind.total_blks);
        }
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
    struct hk_mregion *rg;
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
    struct hk_inode *pi;

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
    // TODO: Fine-grain inode recovery
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
    } else {
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
    struct inode *dir;
    const char *name;
    int name_len;
    u64 ino;
    u16 link_change = 0;

#ifndef CONFIG_FINEGRAIN_JOURNAL
    name_len = je_pd->jdentry.name_len;
    name = je_pd->jdentry.name;

    if (!invalidate) {
        link_change = je_pd->jdentry.links_count;
        ino = le64_to_cpu(je_pd->jdentry.ino);
    } else {
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

#ifndef CONFIG_FINEGRAIN_JOURNAL
    switch (jtype) {
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
            hk_block_symlink(sb, inode, symname, symlen, NULL);
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
        je_pi = hk_get_jentry_by_slotid(sb, txid, 0);     /* self */
        je_pd = hk_get_jentry_by_slotid(sb, txid, 1);     /* self-dentry */
        je_pd_new = hk_get_jentry_by_slotid(sb, txid, 2); /* new-dentry */
        je_pi_par = hk_get_jentry_by_slotid(sb, txid, 3); /* parent */
        je_pi_new = hk_get_jentry_by_slotid(sb, txid, 4); /* new-parent */

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

#define NEED_NORMAL_RECOVERY       0
#define NEED_FORCE_NORMAL_RECOVERY 1
#define NEED_NO_FURTHER_RECOVERY   2

static bool hk_try_normal_recovery(struct super_block *sb, int recovery_flags)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_super_block *super = sbi->hk_sb;
    struct hk_layout_info *layout;
    struct hk_normal_data *nd;
    struct hk_pack_data *pd;
    u64 cur_vtail = 0;
    bool is_failure = false;
    int cpuid;

    if (recovery_flags == NEED_NO_FURTHER_RECOVERY)
        return false;

    if (le32_to_cpu(super->s_valid_umount) == HK_VALID_UMOUNT) {
        hk_dbgv("normal recovery\n");
        goto out;
    } else {
        is_failure = true;
    }

out:
    if (recovery_flags == NEED_FORCE_NORMAL_RECOVERY || !is_failure) {
        if (ENABLE_META_PACK(sb)) {
            pd = (struct hk_pack_data *)(sbi->hk_sb + sizeof(struct hk_super_block));
            hk_create_dram_bufs(sbi);
            /* Traverse create pkg */
            hk_recovery_create_pkgs(sbi, in_dram_bm_buf, in_dram_blk_buf, &cur_vtail);
            /* Traverse unlink pkg */
            hk_recovery_unlink_pkgs(sbi, in_dram_bm_buf, in_dram_blk_buf, &cur_vtail);
            /* Traverse attr pkg */
            hk_recovery_attr_pkgs(sbi, in_dram_bm_buf, in_dram_blk_buf, &cur_vtail);
            /* Traverse data pkg */
            hk_recovery_data_pkgs(sbi, in_dram_bm_buf, in_dram_blk_buf, &cur_vtail);
            hk_destroy_dram_bufs();
            
            atomic64_and(0, &sbi->vtail);
            if (is_failure) {
                atomic64_add(cur_vtail, &sbi->vtail);
            } else {
                /* check version */
                BUG_ON(cur_vtail != le64_to_cpu(pd->s_vtail));
                atomic64_add(le64_to_cpu(pd->s_vtail), &sbi->vtail);
            }
        } else {
            nd = (struct hk_normal_data *)(sbi->hk_sb + sizeof(struct hk_super_block));
            sbi->tstamp = le64_to_cpu(nd->s_tstamp);
            for (cpuid = 0; cpuid < sbi->num_layout; cpuid++) {
                layout = &sbi->layouts[cpuid];
                layout->atomic_counter = le64_to_cpu(nd->s_layout->s_atomic_counter);

                layout->ind.free_blks = le64_to_cpu(nd->s_layout->s_ind.free_blks);
                layout->ind.invalid_blks = le64_to_cpu(nd->s_layout->s_ind.invalid_blks);
                layout->ind.prep_blks = le64_to_cpu(nd->s_layout->s_ind.prep_blks);
                layout->ind.valid_blks = le64_to_cpu(nd->s_layout->s_ind.valid_blks);
                layout->ind.total_blks = le64_to_cpu(nd->s_layout->s_ind.total_blks);
            }
        }
    }
    return is_failure;
}

typedef struct rescuer_work {
    u8 *create_bm;
    u8 *unlink_bm;
    u8 *attr_bm;
    u8 *data_bm;
    u32 probe_start_blk;
    u32 probe_blks;
} rescuer_work_t;

void __assign_rescuer_work(struct hk_sb_info *sbi, u32 rescuer_id, u32 rescuer_num, rescuer_work_t *work)
{
    u32 total_blks = (sbi->initsize - (u64)sbi->fs_start) >> HUNTER_BLK_SHIFT;
    u32 blks_per_rescuer = total_blks / rescuer_num;
    u32 start_blk = rescuer_id * blks_per_rescuer;
    u32 end_blk = (rescuer_id + 1) * blks_per_rescuer;
    u32 probe_start_blk = start_blk;
    u32 probe_blks = blks_per_rescuer;

    if (rescuer_id == rescuer_num - 1) {
        end_blk = total_blks;
        probe_blks = end_blk - start_blk;
    }

    work->create_bm = __hk_get_bm_addr(sbi, NULL, BMBLK_CREATE);
    work->unlink_bm = __hk_get_bm_addr(sbi, NULL, BMBLK_UNLINK);
    work->attr_bm = __hk_get_bm_addr(sbi, NULL, BMBLK_ATTR);
    work->data_bm = __hk_get_bm_addr(sbi, NULL, BMBLK_DATA);
    work->probe_start_blk = probe_start_blk;
    work->probe_blks = probe_blks;    
}

u8 hk_probe_blk(struct hk_sb_info *sbi, u32 blk)
{
    u8 *cur_blk;
    u8 *start_addr;
    u64 in_pm_addr;
    struct hk_obj_hdr *hdr;
    struct hk_pkg_hdr *pkg_hdr;
    u8 probe_type = OBJ_TYPE_NUM;

    cur_blk = __hk_get_blk_addr(sbi, NULL, blk);
    in_pm_addr = get_pm_blk_addr(sbi, blk);
    start_addr = cur_blk;
    while (cur_blk < start_addr + HUNTER_BLK_SIZE) {
        get_pkg_hdr(cur_blk, OBJ_ATTR, (u64 *)&hdr);
        if (check_pkg_valid(cur_blk, MTA_PKG_ATTR_SIZE, hdr) == 0) {
            if (hdr->magic == HUNTER_OBJ_MAGIC) {
                if (hdr->type == OBJ_ATTR) {
                    probe_type = PKG_ATTR;
                    break;
                }
            }
        }
        get_pkg_hdr(cur_blk, OBJ_DATA, (u64 *)&hdr);
        if (check_pkg_valid(cur_blk, MTA_PKG_DATA_SIZE, hdr) == 0) {
            if (hdr->magic == HUNTER_OBJ_MAGIC) {
                if (hdr->type == OBJ_DATA) {
                    probe_type = PKG_ATTR;
                    break;
                }
            }
        }
        get_pkg_hdr(cur_blk, PKG_CREATE, (u64 *)&pkg_hdr);
        if (check_pkg_valid(cur_blk, MTA_PKG_CREATE_SIZE, &pkg_hdr->hdr) == 0) {
            if (pkg_hdr->hdr.magic == HUNTER_OBJ_MAGIC) {
                if (pkg_hdr->hdr.type == PKG_CREATE) {
                    probe_type = PKG_CREATE;
                    break;
                }
            }
        }
        get_pkg_hdr(cur_blk, PKG_UNLINK, (u64 *)&pkg_hdr);
        if (check_pkg_valid(cur_blk, MTA_PKG_UNLINK_SIZE, &pkg_hdr->hdr) == 0) {
            if (pkg_hdr->hdr.magic == HUNTER_OBJ_MAGIC) {
                if (pkg_hdr->hdr.type == PKG_UNLINK) {
                    probe_type = PKG_UNLINK;
                    break;
                }
            }
        }
        cur_blk += HUNTER_MTA_SIZE;
        in_pm_addr += HUNTER_MTA_SIZE;
    }

    return probe_type;
}

typedef struct rescuer_param {
    struct hk_sb_info *sbi;
    u32 rescuer_id;
    u32 rescuer_num;
} rescuer_param_t;

void *hk_bmblk_rescuer(void *args)
{
    rescuer_param_t *param = (rescuer_param_t *)args;
    struct hk_sb_info *sbi = param->sbi;
    u32 rescuer_id = param->rescuer_id;
    u32 rescuer_num = param->rescuer_num;
    rescuer_work_t work;
    u32 cur_blk;
    u64 addr;
    u8 probe_type;

    __assign_rescuer_work(sbi, rescuer_id, rescuer_num, &work);
    
    /* start probe */
    for (cur_blk = work.probe_start_blk; cur_blk < work.probe_start_blk + work.probe_blks; cur_blk++) {
        addr = get_pm_blk_addr(sbi, cur_blk);
        probe_type = hk_probe_blk(sbi, cur_blk);
        switch (probe_type) {
            case PKG_ATTR:
                hk_set_bit(cur_blk, work.attr_bm);
                break;
            case PKG_DATA:
                hk_set_bit(cur_blk, work.data_bm);
                break;
            case PKG_CREATE:
                hk_set_bit(cur_blk, work.create_bm);
                break;
            case PKG_UNLINK:
                hk_set_bit(cur_blk, work.unlink_bm);
                break;
            default:
                break;
        }
    }

    hk_info("Rescuer %d finish\n", rescuer_id);
    kfree(args);
}

static int hk_rescue_bm(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct task_struct **rescuer_threads;
    int i, ret = 0;

    rescuer_threads = (struct task_struct **)kzalloc(sizeof(struct task_struct) * sbi->cpus, GFP_KERNEL);
    if (!rescuer_threads) {
        hk_err(sb, "Allocate rescuer threads failed\n");
        ret = -ENOMEM;
        goto out;
    }

    for (i = 0; i < sbi->cpus; i++) {
        rescuer_param_t *param = (rescuer_param_t *)kzalloc(sizeof(rescuer_param_t), GFP_KERNEL);
        if (!param) {
            hk_err(sb, "Allocate rescuer param failed\n");
            ret = -ENOMEM;
            goto out;
        }
        param->sbi = sbi;
        param->rescuer_id = i;
        param->rescuer_num = sbi->cpus;

        rescuer_threads[i] = kthread_run((void *)hk_bmblk_rescuer, (void *)param, "hk_bmblk_rescuer%d", i);

        if (ret) {
            hk_err(sb, "Create rescuer thread %d failed\n", i);
            goto out;
        }
    }
    
    for (i = 0; i < sbi->cpus; i++) {
        kthread_stop(rescuer_threads[i]);
    }
out:
    return 0;
}

int hk_failure_recovery(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_super_block *hk_sb = sbi->hk_sb;
    struct hk_layout_info *layout;
    struct hk_journal *jnl;
    struct hk_mregion *rg;
    struct hk_header *hdr;
    struct hk_inode *pi;
    u64 not_free_blks = 0;
    u64 blk = 0;
    u64 addr = 0;
    int cpuid, rgid, txid;
    unsigned long irq_flags = 0;
    int ret = NEED_NO_FURTHER_RECOVERY;

    if (ENABLE_META_PACK(sb)) {
        ret = NEED_FORCE_NORMAL_RECOVERY;
        hk_rescue_bm(sb);
    } else {
        ret = NEED_NO_FURTHER_RECOVERY;
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
            layout->atomic_counter = (layout->layout_blks * HK_PBLK_SZ(sbi));

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

                        sm_remove_hdr(sb, pi, hdr);
                    } else { /* Re insert */
                        sbi->tstamp = le64_to_cpu(pi->tstamp);
                        not_free_blks = blk + 1;

                        sm_remove_hdr(sb, pi, hdr);
                        sm_insert_hdr(sb, pi, hdr);
                    }
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
    }

    return ret;
}

int hk_recovery(struct super_block *sb)
{
    bool is_failure = false;
    int ret;

    INIT_TIMING(start);

    hk_dbgv("%s\n", __func__);

    HK_START_TIMING(recovery_t, start);

    is_failure = hk_try_normal_recovery(sb, NEED_NORMAL_RECOVERY);

    if (!is_failure) {
        hk_dbg("HUNTER: Normal shutdown\n");
    } else {
        ret = hk_failure_recovery(sb);
        hk_try_normal_recovery(sb, ret);
    }

    HK_END_TIMING(recovery_t, start);

    return 0;
}
