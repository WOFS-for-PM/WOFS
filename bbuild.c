/*
 * HUNTER (KILLER) Recovery routines.
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

/* normal recovery */
u8 *in_dram_bm_buf = NULL;
u8 *in_dram_blk_buf = NULL;
/* failure recovery */
u8 *in_dram_attr_bm = NULL;
u8 *in_dram_data_bm = NULL;
u8 *in_dram_create_bm = NULL;
u8 *in_dram_unlink_bm = NULL;

typedef struct recovery_pkgs_param {
    u8 *in_dram_bm_buf;
    u8 *in_dram_blk_buf;
    DECLARE_HASHTABLE(min_data_vtail_table, HK_HASH_BITS7);
} recovery_pkgs_param_t;

struct basic_hash_node {
    struct hlist_node hnode;
    u64 key;
    u64 value;
};

#if 1
static struct basic_hash_node *create_basic_hash_node(u64 key, u64 value)
{
    struct basic_hash_node *node = kzalloc(sizeof(struct basic_hash_node), GFP_KERNEL);
    if (!node)
        return NULL;

    node->key = key;
    node->value = value;

    return node;
}

static void free_basic_hash_node(struct basic_hash_node *node)
{
    if (node)
        kfree(node);
}

static int try_insert_min_data_vtail_table(recovery_pkgs_param_t *param, u32 ino, u64 vtail)
{
    struct basic_hash_node *node;

    hash_for_each_possible(param->min_data_vtail_table, node, hnode, ino)
    {
        if (node->key == ino) {
            if (node->value > vtail)
                node->value = vtail;
            return 0;
        }
    }

    node = create_basic_hash_node(ino, vtail);
    if (!node)
        return -ENOMEM;

    hash_add(param->min_data_vtail_table, &node->hnode, ino);

    return 0;
}

static u64 get_min_data_vtail(recovery_pkgs_param_t *param, u32 ino)
{
    struct basic_hash_node *node;

    hash_for_each_possible(param->min_data_vtail_table, node, hnode, ino)
    {
        if (node->key == ino)
            return node->value;
    }

    return 0;
}

static void destroy_min_data_vtail_table(recovery_pkgs_param_t *param)
{
    struct basic_hash_node *node;
    struct hlist_node *tmp;
    int i;

    hash_for_each_safe(param->min_data_vtail_table, i, tmp, node, hnode)
    {
        hash_del(&node->hnode);
        free_basic_hash_node(node);
    }
}
#else
static struct basic_hash_node *
create_basic_hash_node(u64 key, u64 value)
{
    return NULL;
}
static void free_basic_hash_node(struct basic_hash_node *node) {}
static int try_insert_min_data_vtail_table(recovery_pkgs_param_t *param, u32 ino, u64 vtail) { return 0; }
static u64 get_min_data_vtail(recovery_pkgs_param_t *param, u32 ino) { return 0; }
static void destroy_min_data_vtail_table(recovery_pkgs_param_t *param) {}
#endif

#define hk_traverse_bm(sbi, bm, pointed_blk)                                                                                       \
    for (pointed_blk = 0; pointed_blk < ((sbi->pack_layout.tl_per_type_bm_reserved_blks << HUNTER_BLK_SHIFT) << 3); pointed_blk++) \
        if (hk_test_bit(pointed_blk, bm))

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

static u8 *hk_create_dram_blk_buf(struct hk_sb_info *sbi)
{
    u8 *blk_buf = kvzalloc(HK_PBLK_SZ(sbi), GFP_KERNEL);
    if (!blk_buf)
        hk_err(sbi->sb, "failed to allocate blk_buf");

    return blk_buf;
}

static void hk_free_dram_blk_buf(u8 *blk_buf)
{
    if (blk_buf)
        kvfree(blk_buf);
}

static u8 *hk_create_dram_bm_buf(struct hk_sb_info *sbi)
{
    u8 *bm_buf = kvzalloc(BMBLK_SIZE(sbi), GFP_KERNEL);
    if (!bm_buf)
        hk_err(sbi->sb, "failed to allocate bm_buf");

    return bm_buf;
}

static void hk_free_dram_bm_buf(u8 *bm_buf)
{
    if (bm_buf)
        kvfree(bm_buf);
}

static int hk_create_dram_bufs_normal(struct hk_sb_info *sbi)
{
    struct super_block *sb = sbi->sb;
    hk_info("%s: Try to create bitmap buffer: %d bytes\n", __func__, BMBLK_SIZE(sbi));
    in_dram_bm_buf = hk_create_dram_bm_buf(sbi);
    if (!in_dram_bm_buf) {
        return -ENOMEM;
    }

    hk_info("%s: Try to create blk buffer: %d bytes\n", __func__, HK_PBLK_SZ(sbi));
    in_dram_blk_buf = hk_create_dram_blk_buf(sbi);
    if (!in_dram_blk_buf) {
        hk_free_dram_bm_buf(in_dram_bm_buf);
        return -ENOMEM;
    }

    return 0;
}

static void hk_destroy_dram_bufs_normal(void)
{
    if (in_dram_bm_buf)
        kvfree(in_dram_bm_buf);
    if (in_dram_blk_buf)
        kvfree(in_dram_blk_buf);
}

static int hk_create_dram_bufs_failure(struct hk_sb_info *sbi)
{
    struct super_block *sb = sbi->sb;
    hk_info("%s: Try to create 4 bitmap buffer: %d bytes\n", __func__, BMBLK_SIZE(sbi) * 4);

    in_dram_attr_bm = hk_create_dram_bm_buf(sbi);
    if (!in_dram_attr_bm) {
        return -ENOMEM;
    }

    in_dram_data_bm = hk_create_dram_bm_buf(sbi);
    if (!in_dram_data_bm) {
        hk_free_dram_bm_buf(in_dram_attr_bm);
        return -ENOMEM;
    }

    in_dram_create_bm = hk_create_dram_bm_buf(sbi);
    if (!in_dram_create_bm) {
        hk_free_dram_bm_buf(in_dram_attr_bm);
        hk_free_dram_bm_buf(in_dram_data_bm);
        return -ENOMEM;
    }

    in_dram_unlink_bm = hk_create_dram_bm_buf(sbi);
    if (!in_dram_unlink_bm) {
        hk_free_dram_bm_buf(in_dram_attr_bm);
        hk_free_dram_bm_buf(in_dram_data_bm);
        hk_free_dram_bm_buf(in_dram_create_bm);
        return -ENOMEM;
    }

    return 0;
}

static void hk_destroy_dram_bufs_failure(void)
{
    if (in_dram_attr_bm)
        kvfree(in_dram_attr_bm);
    if (in_dram_data_bm)
        kvfree(in_dram_data_bm);
    if (in_dram_create_bm)
        kvfree(in_dram_create_bm);
    if (in_dram_unlink_bm)
        kvfree(in_dram_unlink_bm);
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
        /* apply empirical read model */
        int i, j;
        size_t ra_win = sbi->ra_win;
        size_t win = rounddown_pow_of_two(ra_win / HK_RESCUE_WORKERS);

        for (i = 0; i < HK_PBLK_SZ(sbi); i += win) {
            for (j = i; j < (i + win); j += 256) {
                prefetcht2(get_pm_blk_addr(sbi, blk) + j);
            }
            memcpy(buf + i, get_pm_blk_addr(sbi, blk) + i, win);
        }
        addr = buf;
    } else {
        addr = get_pm_blk_addr(sbi, blk);
    }
    return addr;
}

int hk_recovery_data_pkgs(struct hk_sb_info *sbi, recovery_pkgs_param_t *recovery_param, u64 *max_vtail)
{
    u8 *bm_buf = recovery_param->in_dram_bm_buf;
    u8 *blk_buf = recovery_param->in_dram_blk_buf;
    u8 *cur_addr;
    u8 *data_bm;
    u8 *cur_data;
    u8 *start_addr;
    struct hk_inode *inode;
    struct hk_obj_data *data;
    obj_ref_data_t *ref_data;
    u64 in_pm_addr;
    u64 pm_data_addr;
    tlrestore_param_t param;
    struct hk_obj_hdr *hdr = NULL;
    struct hk_inode_info_header *sih;
    u64 entrynr;
    u32 blk;
    u32 num;
    bool second_chance = false;
    u64 reserved = 0;

    data_bm = __hk_get_bm_addr(sbi, bm_buf, BMBLK_DATA);
    hk_traverse_bm(sbi, data_bm, blk)
    {
        cur_data = __hk_get_blk_addr(sbi, blk_buf, blk);
        in_pm_addr = get_pm_blk_addr(sbi, blk);
        start_addr = cur_data;
        while (cur_data < start_addr + HK_PBLK_SZ(sbi)) {
            get_pkg_hdr(cur_data, PKG_DATA, (u64 *)&hdr);
            if (check_pkg_valid(cur_data, OBJ_DATA_SIZE, hdr)) {
                second_chance = false;
            } else {
                second_chance = true;
            }

            /* NOTE: reserved field is used for append optimization */
            if (second_chance) {
                data = (struct hk_obj_data *)cur_data;
                reserved = data->hdr.reserved;
                data->hdr.reserved = 0;
            }

            if (check_pkg_valid(cur_data, OBJ_DATA_SIZE, hdr)) {
                data = (struct hk_obj_data *)cur_data;
                sih = obj_mgr_get_imap_inode(sbi->pack_layout.obj_mgr, data->ino);
                if (sih) {
                    BUG_ON(1);
                    /* restore data entry */
                    cur_addr = cur_data;
                    entrynr = GET_ENTRYNR(get_pm_offset(sbi, in_pm_addr));
                    num = MTA_PKG_DATA_BLK;
                    tl_build_restore_param(&param, blk, (entrynr << 32 | num), TL_MTA | TL_MTA_PKG_DATA);
                    tlrestore(get_tl_allocator(sbi, get_pm_offset(sbi, in_pm_addr)), &param);

                    /* restore data corresponding to the entry */
                    pm_data_addr = get_pm_blk_addr(sbi, data->blk);
                    tl_build_restore_param(&param, data->blk, data->num, TL_BLK);
                    tlrestore(get_tl_allocator(sbi, get_pm_offset(sbi, pm_data_addr)), &param);
                    ref_data = ref_data_create(get_pm_offset(sbi, in_pm_addr), data->ino, data->ofs, data->num, get_pm_offset(sbi, pm_data_addr));
                    obj_mgr_load_dobj_control(sbi->pack_layout.obj_mgr, ref_data, OBJ_DATA);

                    try_insert_min_data_vtail_table(recovery_param, data->ino, data->hdr.vtail);

                    if (data->hdr.vtail > *max_vtail)
                        *max_vtail = data->hdr.vtail;
                }
            }

            if (second_chance) {
                data = (struct hk_obj_data *)cur_data;
                data->hdr.reserved = reserved;
            }

            cur_data += OBJ_DATA_SIZE;
            in_pm_addr += OBJ_DATA_SIZE;
        }
    }

    return 0;
}

int __check_should_update_attr(struct hk_sb_info *sbi, struct hk_inode_info_header *sih, u64 vtail, bool inline_update)
{
    struct hk_obj_attr *orig_attr;
    struct hk_pkg_hdr *inline_attr;

    if (inline_update) {
        if (!sih->pack_spec.latest_fop.latest_inline_attr) {
            return 1;
        }

        inline_attr = get_pm_addr(sbi, sih->pack_spec.latest_fop.latest_inline_attr);

        if (inline_attr->hdr.vtail < vtail) {
            return 1;
        }
    } else {
        if (!sih->pack_spec.latest_fop.latest_attr) {
            return 1;
        }

        orig_attr = get_pm_addr(sbi, sih->pack_spec.latest_fop.latest_attr->hdr.addr);

        if (orig_attr->hdr.vtail < vtail) {
            return 1;
        }
    }

    return 0;
}

void __hk_build_attr_update_from_pm(struct hk_sb_info *sbi, struct hk_obj_attr *attr, attr_update_t *attr_update)
{
    attr_update->addr = get_pm_offset(sbi, get_pm_offset(sbi, (u64)attr));
    attr_update->from_pkg = PKG_CREATE;
    attr_update->dep_ofs = 0;
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

static int __hk_recovery_attr_from_create_pkg(struct hk_sb_info *sbi, u8 *in_pm_cur_create, bool parent)
{
    struct super_block *sb = sbi->sb;
    struct hk_inode_info_header *sih, *psih;
    attr_update_t attr_update;
    struct hk_obj_inode *obj_inode;
    struct hk_pkg_hdr *pkg_hdr;
    u64 vtail;
    u32 ino;

    obj_inode = (struct hk_obj_inode *)in_pm_cur_create;
    get_pkg_hdr(in_pm_cur_create, PKG_CREATE, (u64 *)&pkg_hdr);
    vtail = pkg_hdr->hdr.vtail;

    if (!parent) {
        ino = obj_inode->ino;
        hk_dbgv("Recovery attr from create pkg, ino %lu, vtail %lu, father %lu\n", ino, vtail, parent);
        sih = obj_mgr_get_imap_inode(sbi->pack_layout.obj_mgr, ino);
        if (!sih) {
            hk_warn("1: Can't find inode %lu in imap\n", ino);
            return -ENOENT;
        } else {
            if (__check_should_update_attr(sbi, sih, vtail, true)) {
                attr_update.addr = get_pm_offset(sbi, pkg_hdr);
                ;
                attr_update.from_pkg = PKG_CREATE;
                attr_update.dep_ofs = 0;
                attr_update.i_atime = attr_update.i_ctime = attr_update.i_mtime = obj_inode->i_create_time;
                attr_update.i_gid = pkg_hdr->create_hdr.attr.i_gid;
                attr_update.i_uid = pkg_hdr->create_hdr.attr.i_uid;
                attr_update.i_mode = pkg_hdr->create_hdr.attr.i_mode;
                attr_update.i_size = 0;
                attr_update.i_links_count = 1;
                attr_update.inline_update = true;
                ur_dram_latest_attr(sbi->pack_layout.obj_mgr, sih, &attr_update);
            }
        }
    } else { /* parent */
        if (obj_inode->ino == HK_ROOT_INO) {
            return 0;
        }
        ino = pkg_hdr->create_hdr.attr.ino;
        hk_dbgv("Recovery attr from create pkg, ino %lu, vtail %lu, father %lu\n", ino, vtail, parent);
        psih = obj_mgr_get_imap_inode(sbi->pack_layout.obj_mgr, ino);
        if (!psih) {
            hk_warn("2: Can't find inode %lu in imap\n", ino);
            return -ENOENT;
        } else {
            if (__check_should_update_attr(sbi, psih, vtail, true)) {
                attr_update.addr = get_pm_offset(sbi, pkg_hdr);
                ;
                attr_update.from_pkg = PKG_CREATE;
                attr_update.dep_ofs = 0;
                attr_update.i_atime = attr_update.i_ctime = attr_update.i_mtime = pkg_hdr->create_hdr.parent_attr.i_cmtime;
                attr_update.i_gid = psih->i_gid;
                attr_update.i_uid = psih->i_uid;
                attr_update.i_mode = psih->i_mode;
                attr_update.i_size = pkg_hdr->create_hdr.parent_attr.i_size;
                attr_update.i_links_count = pkg_hdr->create_hdr.parent_attr.i_links_count;
                attr_update.inline_update = true;
                ur_dram_latest_attr(sbi->pack_layout.obj_mgr, psih, &attr_update);
            }
        }
    }
    return 0;
}

static int __hk_recovery_attr_from_unlink_pkg(struct hk_sb_info *sbi, u8 *in_pm_cur_unlink, bool parent, struct hk_inode_info_header *sih)
{
    struct super_block *sb = sbi->sb;
    struct hk_inode_info_header *psih;
    attr_update_t attr_update;
    struct hk_pkg_hdr *pkg_hdr;
    u64 vtail;
    u32 ino;

    get_pkg_hdr(in_pm_cur_unlink, PKG_UNLINK, (u64 *)&pkg_hdr);
    vtail = pkg_hdr->hdr.vtail;

    if (!parent) {
        /* Do Nothing */
    } else { /* parent */
        ino = pkg_hdr->unlink_hdr.parent_attr.ino;
        hk_dbgv("Recovery attr from create pkg, ino %lu, vtail %lu, father %lu\n", ino, vtail, parent);
        psih = obj_mgr_get_imap_inode(sbi->pack_layout.obj_mgr, ino);
        if (!psih) {
            hk_warn("3: Can't find inode %lu in imap\n", ino);
            return -ENOENT;
        } else {
            if (__check_should_update_attr(sbi, psih, vtail, true)) {
                attr_update.addr = get_pm_offset(sbi, pkg_hdr);
                attr_update.from_pkg = PKG_UNLINK;
                if (sih == NULL) {
                    attr_update.dep_ofs = 0;
                } else {
                    attr_update.dep_ofs = sih->pack_spec.latest_fop.latest_inode->hdr.addr;
                }
                attr_update.i_atime = attr_update.i_ctime = attr_update.i_mtime = pkg_hdr->unlink_hdr.parent_attr.i_cmtime;
                attr_update.i_gid = psih->i_gid;
                attr_update.i_uid = psih->i_uid;
                attr_update.i_mode = psih->i_mode;
                attr_update.i_size = pkg_hdr->unlink_hdr.parent_attr.i_size;
                attr_update.i_links_count = pkg_hdr->unlink_hdr.parent_attr.i_links_count;
                attr_update.inline_update = true;
                ur_dram_latest_attr(sbi->pack_layout.obj_mgr, psih, &attr_update);
            }
        }
    }
    return 0;
}

static int __hk_recovery_from_create_pkg(struct hk_sb_info *sbi, u64 in_buf_create, u64 in_pm_create, u32 blk, u64 *max_vtail)
{
    u8 *cur_addr;
    struct hk_inode_info_header *sih;
    struct hk_obj_inode *obj_inode;
    struct hk_obj_dentry *obj_dentry;
    struct hk_pkg_hdr *pkg_hdr;
    tlrestore_param_t param;
    inode_update_t inode_update;
    obj_ref_dentry_t *ref_dentry;
    d_obj_ref_list_t *dentry_list;
    struct list_head *pos;
    u64 entrynr;
    u32 num;
    int ret, cpuid;
    struct super_block *sb = sbi->sb;
    u64 est_vtail;
    u64 cur_vtail;
    INIT_TIMING(time);
    INIT_TIMING(rec_alloc_time);
    INIT_TIMING(rec_imap_time);
    INIT_TIMING(rec_dobj_time);

    HK_START_TIMING(rec_create_pkg_t, time);
    cur_addr = in_buf_create;
    get_pkg_hdr(cur_addr, PKG_CREATE, (u64 *)&pkg_hdr);

    obj_inode = (struct hk_obj_inode *)cur_addr;
    sih = obj_mgr_get_imap_inode(sbi->pack_layout.obj_mgr, obj_inode->ino);
    cur_vtail = pkg_hdr->hdr.vtail;

    if (sih) {
        est_vtail = ((struct hk_obj_inode *)get_pm_addr(sbi, sih->pack_spec.latest_fop.latest_inode->hdr.addr))->hdr.vtail;
        if (est_vtail < cur_vtail) {
            hk_warn("New Inode @%llx found, Old Inode %lu @%llx is unlinked, but found in imap, which means corresponding CREATE pkg is not used, but ino is reused. We try to remove Old one\n",
                    get_pm_offset(sbi, in_pm_create),
                    sih->ino,
                    sih->pack_spec.latest_fop.latest_inode->hdr.addr);

            obj_mgr_unload_imap_control(sbi->pack_layout.obj_mgr, sih);

            bool found = false;
            for (cpuid = 0; cpuid < sbi->cpus; cpuid++) {
                /* remove from parent */
                obj_mgr_get_dobjs(sbi->pack_layout.obj_mgr, cpuid, pkg_hdr->unlink_hdr.parent_attr.ino, OBJ_DENTRY, (void *)&dentry_list);
                if (dentry_list) {
                    list_for_each(pos, &dentry_list->list)
                    {
                        ref_dentry = container_of(pos, obj_ref_dentry_t, node);
                        if (ref_dentry->target_ino == sih->ino) {
                            reclaim_dram_create(sbi->pack_layout.obj_mgr, sih, ref_dentry);
                            if (sih->pack_spec.latest_fop.latest_attr)
                                ref_attr_destroy(sih->pack_spec.latest_fop.latest_attr);
                            if (sih->pack_spec.latest_fop.latest_inode)
                                ref_inode_destroy(sih->pack_spec.latest_fop.latest_inode);
                            hk_free_hk_inode_info_header(sih);
                            hk_free_obj_ref_dentry(ref_dentry);
                            found = true;
                            break;
                        }
                    }
                    if (found)
                        break;
                }
            }
        } else {
            /* est is the newest one, we just ignore this CREATE PKG */
            hk_info("Inode @%llx found, but Exist Inode %lu @%llx is newer. Thus we omit this Inode\n",
                    get_pm_offset(sbi, in_pm_create),
                    sih->ino,
                    sih->pack_spec.latest_fop.latest_inode->hdr.addr);
            ret = 0;
            goto out;
        }
    }

    if ((in_pm_create & 0x00000000000FFFFF) == 0x00000000000fff00 && blk == 511) {
        hk_info("entrynr %llu, num %lu, blk %u, in_pm_create %llx\n", entrynr, num, blk, in_pm_create);
        tl_dump_allocator(get_tl_allocator(sbi, get_pm_offset(sbi, in_pm_create)));
    }
    
    HK_START_TIMING(rec_allocator_t, rec_alloc_time);
    entrynr = GET_ENTRYNR(get_pm_offset(sbi, in_pm_create));
    num = MTA_PKG_CREATE_BLK;
    tl_build_restore_param(&param, blk, (entrynr << 32 | num), TL_MTA | TL_MTA_PKG_CREATE);
    tlrestore(get_tl_allocator(sbi, get_pm_offset(sbi, in_pm_create)), &param);
    HK_END_TIMING(rec_allocator_t, rec_alloc_time);

    if ((in_pm_create & 0x00000000000FFFFF) == 0x00000000000fff00 && blk == 511) {
        hk_info("entrynr %llu, num %lu, blk %u, in_pm_create %llx\n", entrynr, num, blk, in_pm_create);
        tl_dump_allocator(get_tl_allocator(sbi, get_pm_offset(sbi, in_pm_create)));
    }

    /* control inode */
    sih = hk_alloc_hk_inode_info_header();
    if (!sih) {
        ret = -ENOMEM;
        hk_err(sb, "Create inode failed\n");
        goto out;
    }

    /* init header */
    hk_init_header(sb, sih, pkg_hdr->create_hdr.attr.i_mode);
    
    HK_START_TIMING(rec_imap_t, rec_imap_time);
    __hk_build_inode_update_from_pm(sbi, (struct hk_obj_inode *)in_pm_create, &inode_update);
    ur_dram_latest_inode(sbi->pack_layout.obj_mgr, sih, &inode_update);
    obj_mgr_load_imap_control(sbi->pack_layout.obj_mgr, sih);
    cur_addr += OBJ_INODE_SIZE;
    HK_END_TIMING(rec_imap_t, rec_imap_time);
    
    /* control dentry */
    HK_START_TIMING(rec_dobj_t, rec_dobj_time);
    obj_dentry = (struct hk_obj_dentry *)cur_addr;
    ref_dentry = ref_dentry_create(get_pm_offset(sbi, in_pm_create + OBJ_INODE_SIZE), obj_dentry->name, strlen(obj_dentry->name), obj_inode->ino, obj_dentry->parent_ino);
    obj_mgr_load_dobj_control(sbi->pack_layout.obj_mgr, ref_dentry, OBJ_DENTRY);
    HK_END_TIMING(rec_dobj_t, rec_dobj_time);

    /* apply myself attr based on current create */
    __hk_recovery_attr_from_create_pkg(sbi, in_pm_create, false);

    if (pkg_hdr->hdr.vtail > *max_vtail)
        *max_vtail = pkg_hdr->hdr.vtail;
out:
    HK_END_TIMING(rec_create_pkg_t, time);
    return ret;
}

int hk_recovery_create_pkgs(struct hk_sb_info *sbi, recovery_pkgs_param_t *recovery_param, u64 *max_vtail)
{
    int ret = 0;
    u8 *create_bm;
    u8 *in_buf_create;
    u8 *start_addr;
    u64 in_pm_create;
    struct super_block *sb = sbi->sb;
    struct basic_list_node *lnode;
    tlrestore_param_t param;
    struct hk_pkg_hdr *pkg_hdr;
    struct list_head create_list, *pos, *n;
    u32 blk;
    u8 *bm_buf = recovery_param->in_dram_bm_buf;
    u8 *blk_buf = recovery_param->in_dram_blk_buf;
    u64 checked = 0;

    INIT_LIST_HEAD(&create_list);

    create_bm = __hk_get_bm_addr(sbi, bm_buf, BMBLK_CREATE);
    hk_traverse_bm(sbi, create_bm, blk)
    {
        in_buf_create = __hk_get_blk_addr(sbi, blk_buf, blk);
        in_pm_create = get_pm_blk_addr(sbi, blk);
        start_addr = in_buf_create;
        while (in_buf_create < start_addr + HK_PBLK_SZ(sbi)) {
            get_pkg_hdr(in_buf_create, PKG_CREATE, (u64 *)&pkg_hdr);
            if (check_pkg_valid(in_buf_create, MTA_PKG_CREATE_SIZE, &pkg_hdr->hdr)) {
                /* pend create pkg for processing parent create package */
                lnode = create_basic_list_node(in_pm_create);
                if (!lnode) {
                    ret = -ENOMEM;
                    hk_err(sb, "Create list node failed\n");
                    goto out;
                }
                list_add_tail(&lnode->node, &create_list);

                __hk_recovery_from_create_pkg(sbi, in_buf_create, in_pm_create, blk, max_vtail);
                checked++;
                if (checked % 10000 == 0) {
                    hk_info("%llu pkgs have been checked\n", checked);
                }
            }

            in_buf_create += MTA_PKG_CREATE_SIZE;
            in_pm_create += MTA_PKG_CREATE_SIZE;
        }
    }

    /* control attr */
    list_for_each_safe(pos, n, &create_list)
    {
        lnode = list_entry(pos, struct basic_list_node, node);
        in_pm_create = (u8 *)lnode->value;
        __hk_recovery_attr_from_create_pkg(sbi, in_pm_create, true);
        list_del(pos);
        free_basic_list_node(lnode);
    }

out:
    return ret;
}

static int __hk_recovery_from_unlink_pkg(struct hk_sb_info *sbi, u64 in_buf_unlink, u64 in_pm_unlink, u32 blk, u64 *max_vtail)
{
    struct hk_inode_info_header *sih, *psih;
    tlrestore_param_t param;
    struct list_head *pos;
    obj_ref_dentry_t *ref_dentry;
    struct hk_pkg_hdr *pkg_hdr, *dep_create_pkg_hdr;
    d_obj_ref_list_t *dentry_list;
    u64 dep_create_addr;
    u64 entrynr;
    u32 num;
    u64 est_vtail, dep_vtail, cur_vtail;
    u32 dep_ino;
    int cpuid;
    bool need_free_sih = false;
    INIT_TIMING(time);
    INIT_TIMING(rec_unalloc_time);
    INIT_TIMING(rec_unload_imap_time);
    INIT_TIMING(rec_unload_dobj_time);

    HK_START_TIMING(rec_unlink_pkg_t, time);

    get_pkg_hdr(in_buf_unlink, PKG_UNLINK, (u64 *)&pkg_hdr);
    cur_vtail = pkg_hdr->hdr.vtail;

    /* parse pkg hdr */
    psih = obj_mgr_get_imap_inode(sbi->pack_layout.obj_mgr, pkg_hdr->unlink_hdr.parent_attr.ino);
    if (!psih) {
        hk_warn("Can't find parent inode %lu in imap\n", pkg_hdr->unlink_hdr.parent_attr.ino);
        return -ENOENT;
    }

    sih = obj_mgr_get_imap_inode(sbi->pack_layout.obj_mgr, pkg_hdr->unlink_hdr.unlinked_ino);
    if (sih) {
        est_vtail = ((struct hk_obj_inode *)get_pm_addr(sbi, sih->pack_spec.latest_fop.latest_inode->hdr.addr))->hdr.vtail;
        if (est_vtail < cur_vtail) {
            hk_dbgv("Inode %lu is unlinked, but found in imap, which means corresponding CREATE pkg is not used\n", sih->ino);
            
            HK_START_TIMING(rec_unload_imap_t, rec_unload_imap_time);
            obj_mgr_unload_imap_control(sbi->pack_layout.obj_mgr, sih);
            HK_END_TIMING(rec_unload_imap_t, rec_unload_imap_time);

            for (cpuid = 0; cpuid < sbi->cpus; cpuid++) {
                /* remove from parent */
                obj_mgr_get_dobjs(sbi->pack_layout.obj_mgr, cpuid, pkg_hdr->unlink_hdr.parent_attr.ino, OBJ_DENTRY, (void *)&dentry_list);
                if (dentry_list) {
                    list_for_each(pos, &dentry_list->list)
                    {
                        ref_dentry = container_of(pos, obj_ref_dentry_t, node);
                        if (ref_dentry->target_ino == sih->ino) {
                            HK_START_TIMING(rec_unload_dobj_t, rec_unload_dobj_time);
                            reclaim_dram_create(sbi->pack_layout.obj_mgr, sih, ref_dentry);
                            HK_END_TIMING(rec_unload_dobj_t, rec_unload_dobj_time);
                            hk_free_obj_ref_dentry(ref_dentry);
                            need_free_sih = true;
                            break;
                        }
                    }
                    if (need_free_sih) {
                        break;
                    }
                }
            }
            /* fall thru */
        } else {
            hk_warn("Get UNLINK PKG @0x%llx, but current inode %lu is not unlinked by this pkg \n\
\t\t(since vtail of inode %llu > pkg's %llu). This means the corresponding CREATE PKG for UNLINK PKG @0x%llx \n\
\t\tis either overwritten or not used. Therefore, we perform further check.\n",
                    in_pm_unlink,
                    sih->ino,
                    est_vtail,
                    cur_vtail,
                    in_pm_unlink);
            dep_create_addr = get_pm_addr(sbi, pkg_hdr->unlink_hdr.dep_ofs);
            get_pkg_hdr(dep_create_addr, PKG_CREATE, (u64 *)&dep_create_pkg_hdr);
            if (check_pkg_valid(dep_create_addr, MTA_PKG_CREATE_SIZE, &dep_create_pkg_hdr->hdr)) {
                dep_vtail = dep_create_pkg_hdr->hdr.vtail;
                dep_ino = ((struct hk_obj_inode *)dep_create_addr)->ino;
                if (dep_vtail > cur_vtail) {
                    /* the dep inode is overwritten, the UNLINK PKG can be reclaimed */
                    hk_info("The dep addr @%llx is overwritten, the UNLINK PKG can be reclaimed.\n", dep_create_addr);
                    goto out;
                }
                /* the dep inode is not used */
                hk_info("The dep addr @%llx is not used, we cannot safely free this UNLINK PKG for now.\n", dep_create_addr);
                BUG_ON(dep_ino != sih->ino);
                /* fall thru */
            } else {
                /* the dep inode is partially overwritten, the UNLINK PKG can be reclaimed */
                hk_info("The dep addr @%llx is partially overwritten, the UNLINK PKG can be reclaimed.\n", dep_create_addr);
                goto out;
            }
        }
        
        HK_START_TIMING(rec_unalloc_t, rec_unalloc_time);
        entrynr = GET_ENTRYNR(get_pm_offset(sbi, in_pm_unlink));
        num = MTA_PKG_UNLINK_BLK;
        tl_build_restore_param(&param, blk, (entrynr << 32 | num), TL_MTA | TL_MTA_PKG_UNLINK);
        tlrestore(get_tl_allocator(sbi, get_pm_offset(sbi, in_pm_unlink)), &param);
        HK_END_TIMING(rec_unalloc_t, rec_unalloc_time);

        __hk_recovery_attr_from_unlink_pkg(sbi, in_pm_unlink, true, sih);

        if (need_free_sih) {
            if (sih->pack_spec.latest_fop.latest_attr)
                ref_attr_destroy(sih->pack_spec.latest_fop.latest_attr);
            if (sih->pack_spec.latest_fop.latest_inode)
                ref_inode_destroy(sih->pack_spec.latest_fop.latest_inode);
            hk_free_hk_inode_info_header(sih);
        }
    }

out:
    if (pkg_hdr->hdr.vtail > *max_vtail)
        *max_vtail = pkg_hdr->hdr.vtail;

    HK_END_TIMING(rec_unlink_pkg_t, time);
    return 0;
}

extern pendlst_t *obj_mgr_get_pendlst(obj_mgr_t *mgr, u64 dep_pkg_addr);

int hk_recovery_unlink_pkgs(struct hk_sb_info *sbi, recovery_pkgs_param_t *recovery_param, u64 *max_vtail)
{
    int ret = 0;
    u8 *unlink_bm;
    u8 *in_buf_unlink;
    u64 in_pm_unlink;
    u8 *start_addr;
    struct hk_pkg_hdr *pkg_hdr;
    struct basic_list_node *lnode;
    u8 *in_pm_rename_unlink, *in_pm_rename_create;
    struct hk_pkg_hdr *rename_unlink_pkg_hdr, *rename_create_pkg_hdr;
    struct list_head rename_unlink_list, *pos, *n;
    pendlst_t *pendlst;
    u32 blk;
    u8 *bm_buf = recovery_param->in_dram_bm_buf;
    u8 *blk_buf = recovery_param->in_dram_blk_buf;

    INIT_LIST_HEAD(&rename_unlink_list);

    /* check and clean all unlink pkg */
    unlink_bm = __hk_get_bm_addr(sbi, bm_buf, BMBLK_UNLINK);
    hk_traverse_bm(sbi, unlink_bm, blk)
    {
        in_buf_unlink = __hk_get_blk_addr(sbi, blk_buf, blk);
        in_pm_unlink = get_pm_blk_addr(sbi, blk);
        start_addr = in_buf_unlink;
        while (in_buf_unlink < start_addr + HK_PBLK_SZ(sbi)) {
            get_pkg_hdr(in_buf_unlink, PKG_UNLINK, (u64 *)&pkg_hdr);
            if (check_pkg_valid(in_buf_unlink, MTA_PKG_UNLINK_SIZE, &pkg_hdr->hdr)) {
                pkg_hdr = (struct hk_pkg_hdr *)in_buf_unlink;

                if (HK_PKG_TO_BIN_TYPE(pkg_hdr->pkg_type) == BIN_RENAME) {
                    lnode = create_basic_list_node(in_pm_unlink);
                    if (!lnode) {
                        ret = -ENOMEM;
                        hk_err(sbi->sb, "Create list node failed\n");
                        goto out;
                    }
                    list_add_tail(&lnode->node, &rename_unlink_list);
                    continue;
                }

                __hk_recovery_from_unlink_pkg(sbi, in_buf_unlink, in_pm_unlink, blk, max_vtail);
            }
            in_buf_unlink += MTA_PKG_UNLINK_SIZE;
            in_pm_unlink += MTA_PKG_UNLINK_SIZE;
        }
    }

    /* process rename bin */
    list_for_each_safe(pos, n, &rename_unlink_list)
    {
        bool need_revert = false;
        lnode = list_entry(pos, struct basic_list_node, node);
        in_pm_rename_unlink = (u8 *)lnode->value;
        get_pkg_hdr(in_pm_rename_unlink, PKG_UNLINK, (u64 *)&rename_unlink_pkg_hdr);
        in_pm_rename_create = get_pm_addr(sbi, rename_unlink_pkg_hdr->hdr.reserved);
        get_pkg_hdr(in_pm_rename_create, PKG_CREATE, (u64 *)&rename_create_pkg_hdr);

        /* create pkg is not valid */
        if (!check_pkg_valid(in_pm_rename_create, MTA_PKG_CREATE_SIZE, &rename_create_pkg_hdr->hdr)) {
            pendlst = obj_mgr_get_pendlst(sbi->pack_layout.obj_mgr, rename_create_pkg_hdr);
            /* and no UNLINK depends on this create pkg */
            if (!pendlst) {
                need_revert = true;
            }
        }

        if (need_revert) {
            /* Do nothing, ignore this rename_unlink, it's already broken. Rename never happens. */
        } else {
            /* Normally Re-Process UNLINK */
            blk = get_pm_blk(sbi, in_pm_rename_unlink);
            __hk_recovery_from_unlink_pkg(sbi, in_pm_rename_unlink, in_pm_rename_unlink, blk, max_vtail);
        }

        list_del(pos);
        free_basic_list_node(lnode);
    }

out:
    return ret;
}

static int __hk_recovery_from_attr_pkg(struct hk_sb_info *sbi, u64 in_buf_attr, u64 in_pm_attr,
                                       recovery_pkgs_param_t *recovery_param, u32 blk, u64 *max_vtail)
{
    tlrestore_param_t param;
    tlfree_param_t free_param;
    struct hk_inode_info_header *sih;
    struct hk_obj_attr *attr;
    attr_update_t attr_update;
    d_obj_ref_list_t *data_list;
    struct list_head invalid_data_list;
    struct list_head *pos, *n;
    struct basic_list_node *lnode;
    obj_ref_data_t *ref_data;
    u64 entrynr;
    u32 num;
    u64 min_data_vtail = 0;
    u64 data_vtail;
    int ret = 0, cpuid;

    attr = (struct hk_obj_attr *)in_buf_attr;
    sih = obj_mgr_get_imap_inode(sbi->pack_layout.obj_mgr, attr->ino);
    if (!sih) {
        hk_dbgv("4: Can't find inode %lu in imap\n", attr->ino);
        ret = -ENOENT;
        goto out;
    }
    
    BUG_ON(1);
    INIT_LIST_HEAD(&invalid_data_list);

    if (__check_should_update_attr(sbi, sih, attr->hdr.vtail, false)) {
        min_data_vtail = get_min_data_vtail(recovery_param, sih->ino);
        if (attr->hdr.vtail > min_data_vtail) {
            for (cpuid = 0; cpuid < sbi->cpus; cpuid++) {
                /* scanning data list */
                obj_mgr_get_dobjs(sbi->pack_layout.obj_mgr, cpuid, sih->ino, OBJ_DATA, (void *)&data_list);
                if (data_list) {
                    list_for_each(pos, &data_list->list)
                    {
                        ref_data = list_entry(pos, obj_ref_data_t, node);
                        data_vtail = ((struct hk_obj_data *)get_pm_addr(sbi, ref_data->hdr.addr))->hdr.vtail;
                        if (data_vtail < attr->hdr.vtail) {
                            if (ref_data->ofs >= attr->i_size) {
                                /* totally overlapped */

                                /* free data entry */
                                entrynr = GET_ENTRYNR(ref_data->hdr.addr);
                                num = MTA_PKG_DATA_BLK;
                                tl_build_free_param(&free_param, get_pm_blk(sbi, get_pm_addr(sbi, ref_data->hdr.addr)), (entrynr << 32 | num), TL_MTA | TL_MTA_PKG_DATA);
                                tlfree(get_tl_allocator(sbi, ref_data->hdr.addr), &free_param);

                                /* free data corresponding to the entry */
                                tl_build_free_param(&free_param, get_pm_blk(sbi, get_pm_addr(sbi, ref_data->data_offset)), ref_data->num, TL_BLK);
                                tlfree(get_tl_allocator(sbi, ref_data->data_offset), &free_param);

                                /* free ref_data later */
                                lnode = create_basic_list_node(ref_data);
                                if (!lnode) {
                                    hk_err(sbi->sb, "Can't create basic list node\n");
                                    ret = -ENOMEM;
                                    goto out;
                                }
                                list_add_tail(&lnode->node, &invalid_data_list);
                            } else if (ref_data->ofs < attr->i_size && ref_data->ofs + (ref_data->num << PAGE_SHIFT) >= attr->i_size) {
                                u32 reclaimed_blk;
                                u32 reclaimed_blks;

                                num = (_round_up(attr->i_size - ref_data->ofs, HUNTER_BLK_SIZE)) >> PAGE_SHIFT;
                                reclaimed_blks = ref_data->num - num;
                                reclaimed_blk = get_pm_blk(sbi, get_pm_addr(sbi, ref_data->data_offset)) + (ref_data->num - reclaimed_blks);
                                /* free truncated data */
                                tl_build_free_param(&free_param, reclaimed_blk, reclaimed_blks, TL_BLK);
                                tlfree(get_tl_allocator(sbi, get_pm_blk_offset(sbi, reclaimed_blk)), &free_param);

                                /* partially overlapped */
                                ref_data->num = num;
                                memset_nt(get_pm_addr(sbi, ref_data->data_offset) + (attr->i_size - ref_data->ofs), 0, ref_data->num << PAGE_SHIFT - (attr->i_size - ref_data->ofs));
                            }
                        }
                    }
                }
            }
        } else {
            /* Do nothing */
        }

        /* free invalid data ref */
        list_for_each_safe(pos, n, &invalid_data_list)
        {
            lnode = list_entry(pos, struct basic_list_node, node);
            ref_data = (obj_ref_data_t *)lnode->value;
            obj_mgr_unload_dobj_control(sbi->pack_layout.obj_mgr, ref_data, OBJ_DATA);
            ref_data_destroy(ref_data);
            list_del(&lnode->node);
            free_basic_list_node(lnode);
        }

        entrynr = GET_ENTRYNR(get_pm_offset(sbi, in_pm_attr));
        num = MTA_PKG_ATTR_BLK;
        tl_build_restore_param(&param, blk, (entrynr << 32 | num), TL_MTA | TL_MTA_PKG_ATTR);
        tlrestore(get_tl_allocator(sbi, get_pm_offset(sbi, in_pm_attr)), &param);

        __hk_build_attr_update_from_pm(sbi, attr, &attr_update);
        ur_dram_latest_attr(sbi->pack_layout.obj_mgr, sih, &attr_update);
    }

    if (attr->hdr.vtail > *max_vtail)
        *max_vtail = attr->hdr.vtail;

out:
    return ret;
}

int hk_recovery_attr_pkgs(struct hk_sb_info *sbi, recovery_pkgs_param_t *recovery_param, u64 *max_vtail)
{
    u8 *bm_buf = recovery_param->in_dram_bm_buf;
    u8 *blk_buf = recovery_param->in_dram_blk_buf;
    int ret = 0;
    u8 *attr_bm;
    u8 *in_buf_attr;
    u64 in_pm_attr;
    u8 *start_addr;
    u32 blk;
    struct hk_obj_hdr *hdr;

    /* check and clean all attr pkg */
    attr_bm = __hk_get_bm_addr(sbi, bm_buf, BMBLK_ATTR);
    hk_traverse_bm(sbi, attr_bm, blk)
    {
        in_buf_attr = __hk_get_blk_addr(sbi, blk_buf, blk);
        in_pm_attr = get_pm_blk_addr(sbi, blk);
        start_addr = in_buf_attr;
        while (in_buf_attr < start_addr + HK_PBLK_SZ(sbi)) {
            get_pkg_hdr(in_buf_attr, PKG_ATTR, (u64 *)&hdr);
            if (check_pkg_valid(in_buf_attr, MTA_PKG_ATTR_SIZE, hdr)) {
                /* parse attr */
                __hk_recovery_from_attr_pkg(sbi, in_buf_attr, in_pm_attr, recovery_param, blk, max_vtail);
            }
            in_buf_attr += MTA_PKG_ATTR_SIZE;
            in_pm_attr += MTA_PKG_ATTR_SIZE;
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

void hk_set_bm(struct hk_sb_info *sbi, u16 bmblk, u64 blk)
{
    u8 *bm;
    unsigned long flags = 0;
    struct super_block *sb = sbi->sb;
    INIT_TIMING(time);

    HK_START_TIMING(imm_set_bm_t, time);

    bm = __hk_get_bm_addr(sbi, NULL, bmblk);

    hk_memunlock_bm(sb, bmblk, &flags);
    hk_set_bit(blk, bm);
    /* NOTE: the bm is then fenced together with the first */
    /* written entry in the corresponding container */
    hk_flush_buffer(bm + (blk >> 3), CACHELINE_SIZE, false);
    hk_memlock_bm(sb, bmblk, &flags);

    HK_END_TIMING(imm_set_bm_t, time);
}

void hk_clear_bm(struct hk_sb_info *sbi, u16 bmblk, u64 blk)
{
    u8 *bm;
    unsigned long flags = 0;
    struct super_block *sb = sbi->sb;
    INIT_TIMING(time);

    HK_START_TIMING(imm_clear_bm_t, time);

    bm = __hk_get_bm_addr(sbi, NULL, bmblk);

    hk_memunlock_bm(sb, bmblk, &flags);
    hk_clear_bit(blk, bm);
    /* NOTE: the bm is then fenced together with the first */
    /* written entry in the corresponding container */
    hk_flush_buffer(bm + (blk >> 3), CACHELINE_SIZE, false);
    hk_memlock_bm(sb, bmblk, &flags);

    HK_END_TIMING(imm_clear_bm_t, time);
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

    switch (bmblk) {
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
        tmeta_mgr = meta_mgr->tmeta_mgrs[meta_type_to_idx(m_alloc_type)];

        hash_for_each(tmeta_mgr->used_blks, bkt, cur, hnode)
        {
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
        pd = (struct hk_pack_data *)(((void *)hk_sb) + sizeof(struct hk_super_block));
        pd->s_vtail = cpu_to_le64(atomic64_read(&sbi->pack_layout.vtail));
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
            nd = (struct hk_normal_data *)(((void *)hk_sb) + sizeof(struct hk_super_block));
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

    for (rgid = 0; rgid < sbi->norm_layout.rg_slots; rgid++) {
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

void generate_packages(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    // FIXME: assume use 8 threads for recovery for each pass
    unsigned long num_blocks = sbi->num_blocks / 8;
    unsigned long ino, saved_ino;
    obj_ref_inode_t ref_inode;
    struct hk_inode_info_header fake_sih;
    u64 create_start_addr = 0, cur_create_addr;
    
    // NOTE: we have generate root inode
    char name_buf[HUNTER_MAX_NAME_LEN];
    
    hk_info("Generating packages...\n");
    hk_init_header(sb, &fake_sih, S_IFPSEUDO);
    for (ino = 1; ino < num_blocks; ino++) {
        // generate fake inode
        in_pkg_param_t create_param;
        out_pkg_param_t out_param;
        in_create_pkg_param_t in_create_param;
        out_create_pkg_param_t out_create_param;
        snprintf(name_buf, HUNTER_MAX_NAME_LEN, "test-%lu", ino);
        in_create_param.create_type = CREATE_FOR_FAKE;
        in_create_param.new_ino = ino;
        create_param.private = &in_create_param;

        out_param.private = &out_create_param;
        create_param.cur_pkg_addr = 0;
        create_param.bin = false;
        create_new_inode_pkg(sbi, S_IFREG, name_buf, &fake_sih, sbi->pack_layout.rih, &create_param, &out_param);
        
        if (!create_start_addr) {
            create_start_addr = out_param.addr;
        }
    }

    cur_create_addr = create_start_addr;
    for (ino = 1; ino < num_blocks; ino++) {
        ref_inode.hdr.addr = get_pm_offset(sbi, cur_create_addr);
        ref_inode.hdr.ino = ino;
        fake_sih.pack_spec.latest_fop.latest_inode = &ref_inode;
        fake_sih.ino = ino;

        // generate data
        in_pkg_param_t data_param;
        out_pkg_param_t out_data_param;
        
        // NOTE: this data package should never be consulted
        data_param.bin = false;
        data_param.private = (void *)1;
        create_data_pkg(sbi, &fake_sih, 0, 0, 0, 0, &data_param, &out_data_param);
        
        cur_create_addr += MTA_PKG_CREATE_SIZE;
    }

    cur_create_addr = create_start_addr;
    for (ino = 1; ino < num_blocks; ino++) {
        ref_inode.hdr.addr = get_pm_offset(sbi, cur_create_addr);
        ref_inode.hdr.ino = ino;
        fake_sih.pack_spec.latest_fop.latest_inode = &ref_inode;
        fake_sih.ino = ino;

        // generate attr
        in_pkg_param_t attr_param;
        out_pkg_param_t out_attr_param;
        
        attr_param.private = (void *)1;
        create_attr_pkg(sbi, &fake_sih, 0, 0, &attr_param, &out_attr_param);

        cur_create_addr += MTA_PKG_CREATE_SIZE;
    }

    cur_create_addr = create_start_addr;
    for (ino = 1; ino < num_blocks; ino++) {
        ref_inode.hdr.addr = get_pm_offset(sbi, cur_create_addr);
        ref_inode.hdr.ino = ino;
        fake_sih.pack_spec.latest_fop.latest_inode = &ref_inode;
        fake_sih.ino = ino;
        
        // generate unlink
        in_pkg_param_t unlink_param;
        out_pkg_param_t out_unlink_param;
        
        unlink_param.bin = false;
        unlink_param.cur_pkg_addr = 0;
        unlink_param.private = (void *)1;
        
        create_unlink_pkg(sbi, &fake_sih, sbi->pack_layout.rih, NULL, &unlink_param, &out_unlink_param);
        cur_create_addr += MTA_PKG_CREATE_SIZE;
    }
    hk_info("Generating done...\n");
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

    recovery_pkgs_param_t recovery_param = {
        in_dram_blk_buf = in_dram_blk_buf,
        in_dram_bm_buf = in_dram_bm_buf,
    };

    if (recovery_flags == NEED_NO_FURTHER_RECOVERY)
        return false;

    if (le32_to_cpu(super->s_valid_umount) == HK_VALID_UMOUNT) {
        hk_dbg("Start normal recovery\n");
    } else {
        hk_dbg("Start failure recovery\n");
        is_failure = true;
    }

    /* TODO: Handle RENAME and SYMLINK  */
    if (recovery_flags == NEED_FORCE_NORMAL_RECOVERY || !is_failure) {
        if (ENABLE_META_PACK(sb)) {
            pd = (struct hk_pack_data *)((char *)sbi->hk_sb + sizeof(struct hk_super_block));
            hk_create_dram_bufs_normal(sbi);
            /* Traverse create pkg */
            hk_info("Recover create pkgs\n");
            hk_recovery_create_pkgs(sbi, &recovery_param, &cur_vtail);
            /* Traverse unlink pkg */
            hk_info("Recover unlink pkgs\n");
            hk_recovery_unlink_pkgs(sbi, &recovery_param, &cur_vtail);
            /* Traverse data pkg */
            hk_info("Recover data pkgs\n");
            hk_recovery_data_pkgs(sbi, &recovery_param, &cur_vtail);
            /* Traverse attr pkg */
            hk_info("Recover attr pkgs\n");
            hk_recovery_attr_pkgs(sbi, &recovery_param, &cur_vtail);
            
            hk_info("Done traversing pkgs\n");

            destroy_min_data_vtail_table(&recovery_param);
            hk_destroy_dram_bufs_normal();

            atomic64_and(0, &sbi->pack_layout.vtail);
            if (is_failure) {
                atomic64_add(cur_vtail, &sbi->pack_layout.vtail);
            } else {
                /* check version */
                BUG_ON(cur_vtail != le64_to_cpu(pd->s_vtail));
                atomic64_add(le64_to_cpu(pd->s_vtail), &sbi->pack_layout.vtail);
            }
        } else {
            nd = (struct hk_normal_data *)((char *)sbi->hk_sb + sizeof(struct hk_super_block));
            sbi->norm_layout.tstamp = le64_to_cpu(nd->s_tstamp);
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

wait_queue_head_t finish_wq;
int *finished;

static void wait_to_finish(int cpus)
{
    int i;

    for (i = 0; i < cpus; i++) {
        while (finished[i] == 0) {
            wait_event_interruptible_timeout(finish_wq, false,
                                             msecs_to_jiffies(1));
        }
    }
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
    u32 total_blks = (sbi->initsize >> HUNTER_BLK_SHIFT);
    u32 blks_per_rescuer = total_blks / rescuer_num;
    u32 start_blk = rescuer_id * blks_per_rescuer;
    u32 end_blk = (rescuer_id + 1) * blks_per_rescuer;
    u32 probe_start_blk = start_blk;
    u32 probe_blks = blks_per_rescuer;

    if (rescuer_id == rescuer_num - 1) {
        end_blk = total_blks;
        probe_blks = end_blk - start_blk;
    }

    work->create_bm = in_dram_create_bm; // __hk_get_bm_addr(sbi, in_dram_create_bm, BMBLK_CREATE);
    work->unlink_bm = in_dram_unlink_bm; // __hk_get_bm_addr(sbi, in_dram_unlink_bm, BMBLK_UNLINK);
    work->attr_bm = in_dram_attr_bm;     // __hk_get_bm_addr(sbi, in_dram_attr_bm, BMBLK_ATTR);
    work->data_bm = in_dram_data_bm;     // __hk_get_bm_addr(sbi, in_dram_data_bm, BMBLK_DATA);
    work->probe_start_blk = probe_start_blk;
    work->probe_blks = probe_blks;
}

u32 hk_probe_hint(struct hk_sb_info *sbi, u8 *cur_blk)
{
    struct killer_bhint_hdr *bhint_hdr;
    u32 orig_hcrc32, orig_bcrc32;
    u32 calc_hcrc32, calc_bcrc32;
    u32 hint = KILLER_HINT_OCCPY_BLK;

    bhint_hdr = (struct killer_bhint_hdr *)cur_blk;
    orig_hcrc32 = bhint_hdr->hcrc32;
    orig_bcrc32 = bhint_hdr->bcrc32;

    /* check hdr valid */
    bhint_hdr->hcrc32 = 0;
    calc_hcrc32 = hk_crc32c(~0, (u8 *)bhint_hdr, sizeof(struct killer_bhint_hdr));

    if (calc_hcrc32 != orig_hcrc32) {
        goto out;
    }

    /* check hint */
    hint = bhint_hdr->hint;
    if (bhint_hdr->hint == KILLER_HINT_EMPTY_BLK) {
        bhint_hdr->bcrc32 = 0;
        calc_bcrc32 = hk_crc32c(~0, cur_blk, HK_PBLK_SZ(sbi));
        if (calc_bcrc32 != orig_bcrc32) {
            hint = KILLER_HINT_OCCPY_BLK;
            goto out;
        }
    }

out:
    bhint_hdr->hcrc32 = orig_hcrc32;
    bhint_hdr->bcrc32 = orig_bcrc32;
    return hint;
}

u8 hk_probe_blk(struct hk_sb_info *sbi, u8 *local_blk_buf, u32 blk)
{
    u8 *cur_blk;
    u8 *start_addr;
    u64 in_pm_addr;
    u64 remained_size;
    struct hk_obj_hdr *hdr;
    struct hk_pkg_hdr *pkg_hdr;
    u8 probe_type = PKG_TYPE_NUM;
    u32 hint;

    cur_blk = __hk_get_blk_addr(sbi, local_blk_buf, blk);
    in_pm_addr = get_pm_blk_addr(sbi, blk);
    remained_size = HK_PBLK_SZ(sbi);
    start_addr = cur_blk;

    hint = hk_probe_hint(sbi, cur_blk);
    if (hint == KILLER_HINT_EMPTY_BLK) {
        goto out;
    }

    while (cur_blk < start_addr + HK_PBLK_SZ(sbi)) {
        if (remained_size >= MTA_PKG_ATTR_SIZE) {
            get_pkg_hdr(cur_blk, PKG_ATTR, (u64 *)&hdr);
            if (check_pkg_valid(cur_blk, MTA_PKG_ATTR_SIZE, hdr)) {
                if (hdr->magic == HUNTER_OBJ_MAGIC) {
                    if (hdr->type == OBJ_ATTR) {
                        probe_type = PKG_ATTR;
                        break;
                    }
                }
            }
        }

        if (remained_size >= MTA_PKG_DATA_SIZE) {
            get_pkg_hdr(cur_blk, PKG_DATA, (u64 *)&hdr);
            if (check_pkg_valid(cur_blk, MTA_PKG_DATA_SIZE, hdr)) {
                if (hdr->magic == HUNTER_OBJ_MAGIC) {
                    if (hdr->type == OBJ_DATA) {
                        probe_type = PKG_DATA;
                        break;
                    }
                }
            }
        }

        if (remained_size >= MTA_PKG_CREATE_SIZE) {
            get_pkg_hdr(cur_blk, PKG_CREATE, (u64 *)&pkg_hdr);
            if (check_pkg_valid(cur_blk, MTA_PKG_CREATE_SIZE, &pkg_hdr->hdr)) {
                if (pkg_hdr->hdr.magic == HUNTER_OBJ_MAGIC) {
                    if (pkg_hdr->pkg_type == PKG_CREATE) {
                        probe_type = PKG_CREATE;
                        break;
                    }
                }
            }
        }

        if (remained_size >= MTA_PKG_UNLINK_SIZE) {
            get_pkg_hdr(cur_blk, PKG_UNLINK, (u64 *)&pkg_hdr);
            if (check_pkg_valid(cur_blk, MTA_PKG_UNLINK_SIZE, &pkg_hdr->hdr)) {
                if (pkg_hdr->hdr.magic == HUNTER_OBJ_MAGIC) {
                    if (pkg_hdr->pkg_type == PKG_UNLINK) {
                        probe_type = PKG_UNLINK;
                        break;
                    }
                }
            }
        }

        cur_blk += HUNTER_MTA_SIZE;
        in_pm_addr += HUNTER_MTA_SIZE;
        remained_size -= HUNTER_MTA_SIZE;
    }

out:
    return probe_type;
}

typedef struct rescuer_param {
    struct hk_sb_info *sbi;
    u32 rescuer_id;
    u32 rescuer_num;
    u8 *local_blk_buf;
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
    hk_dbgv("Rescuer %d start blk %d, end blk %d, probe blks %d\n", rescuer_id, work.probe_start_blk, work.probe_start_blk + work.probe_blks - 1, work.probe_blks);

    /* start probe */
    for (cur_blk = work.probe_start_blk; cur_blk < work.probe_start_blk + work.probe_blks; cur_blk++) {
        addr = get_pm_blk_addr(sbi, cur_blk);
        probe_type = hk_probe_blk(sbi, param->local_blk_buf, cur_blk);
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

        if (probe_type != PKG_TYPE_NUM) {
            hk_dbgv("Rescuer %d probe blk %d (%s), addr 0x%llx\n", rescuer_id, cur_blk, probe_type == PKG_ATTR ? "ATTR" : probe_type == PKG_DATA ? "DATA"
                                                                                                                      : probe_type == PKG_CREATE ? "CREATE"
                                                                                                                      : probe_type == PKG_UNLINK ? "UNLINK"
                                                                                                                                                 : "UNKNOWN",
                    addr);
        }
        /* be nice */
        schedule();
    }

    finished[rescuer_id] = 1;
    wake_up_interruptible(&finish_wq);
    hk_info("Rescuer %d finish\n", rescuer_id);
    kfree(args);
    do_exit(0);

    return NULL;
}

static int hk_rescue_bm(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct task_struct **rescuer_threads;
    int i, ret = 0;
    u32 rescuer_num = HK_RESCUE_WORKERS;

    hk_info("Rescue bitmap with %d rescuers\n", rescuer_num);

    init_waitqueue_head(&finish_wq);

    hk_create_dram_bufs_failure(sbi);

    rescuer_threads = (struct task_struct **)kzalloc(sizeof(struct task_struct) * rescuer_num, GFP_KERNEL);
    if (!rescuer_threads) {
        hk_err(sb, "Allocate rescuer threads failed\n");
        ret = -ENOMEM;
        goto out;
    }

    finished = kcalloc(rescuer_num, sizeof(int), GFP_KERNEL);
    if (!finished) {
        hk_err(sb, "Allocate finished array failed\n");
        ret = -ENOMEM;
        goto out;
    }
    memset(finished, 0, sizeof(int) * rescuer_num);

    for (i = 0; i < rescuer_num; i++) {
        rescuer_param_t *param = (rescuer_param_t *)kzalloc(sizeof(rescuer_param_t), GFP_KERNEL);
        if (!param) {
            hk_err(sb, "Allocate rescuer param failed\n");
            ret = -ENOMEM;
            goto out;
        }
        param->sbi = sbi;
        param->rescuer_id = i;
        param->rescuer_num = rescuer_num;
        param->local_blk_buf = hk_create_dram_blk_buf(sbi);

        rescuer_threads[i] = kthread_create((void *)hk_bmblk_rescuer, (void *)param, "hk_bmblk_rescuer%d", i);
        if (IS_ERR(rescuer_threads[i])) {
            hk_err(sb, "Create rescuer thread %d failed\n", i);
            ret = PTR_ERR(rescuer_threads[i]);
            goto out;
        }
        kthread_bind(rescuer_threads[i], i);
        wake_up_process(rescuer_threads[i]);

        if (ret) {
            hk_err(sb, "Create rescuer thread %d failed\n", i);
            goto out;
        }
    }

    wait_to_finish(rescuer_num);

    /* aggregate bm buffers to pm */
    memcpy_to_pmem_nocache(__hk_get_bm_addr(sbi, NULL, BMBLK_CREATE), in_dram_create_bm, BMBLK_SIZE(sbi));
    memcpy_to_pmem_nocache(__hk_get_bm_addr(sbi, NULL, BMBLK_UNLINK), in_dram_unlink_bm, BMBLK_SIZE(sbi));
    memcpy_to_pmem_nocache(__hk_get_bm_addr(sbi, NULL, BMBLK_ATTR), in_dram_attr_bm, BMBLK_SIZE(sbi));
    memcpy_to_pmem_nocache(__hk_get_bm_addr(sbi, NULL, BMBLK_DATA), in_dram_data_bm, BMBLK_SIZE(sbi));

out:
    kfree(finished);
    kfree(rescuer_threads);
    hk_destroy_dram_bufs_failure();
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
        // hk_rescue_bm(sb);
    } else {
        ret = NEED_NO_FURTHER_RECOVERY;
        /* Revisiting Meta Regions Here */
        for (rgid = 0; rgid < sbi->norm_layout.rg_slots; rgid++) {
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
                        sbi->norm_layout.tstamp = le64_to_cpu(pi->tstamp);
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
        for (txid = 0; txid < sbi->norm_layout.j_slots; txid++) {
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
