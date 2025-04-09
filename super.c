/*
 * BRIEF DESCRIPTION
 *
 * Super block operations.
 *
 * Copyright 2022-2023 Regents of the University of Harbin Institute of Technology, Shenzhen
 * Computer science and technology, Yanqi Pan <deadpoolmine@qq.com>
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
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

#include <linux/bitops.h>
#include <linux/cred.h>
#include <linux/ctype.h>
#include <linux/dax.h>
#include <linux/exportfs.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/magic.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/parser.h>
#include <linux/random.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vfs.h>
#include <uapi/linux/mount.h>

#include "hunter.h"

int measure_timing;
int wprotect;
int support_clwb;

module_param(measure_timing, int, 0444);
MODULE_PARM_DESC(measure_timing, "Timing measurement");

module_param(wprotect, int, 0444);
MODULE_PARM_DESC(wprotect, "Write-protect pmem region and use CR0.WP to allow updates");

module_param(hk_dbgmask, int, 0444);
MODULE_PARM_DESC(hk_dbgmask, "Control debugging output");

static struct super_operations hk_sops;
static const struct export_operations hk_export_ops;
static struct kmem_cache *hk_inode_cachep;

static struct inode *hk_alloc_inode(struct super_block *sb)
{
    struct hk_inode_info *vi;

    vi = kmem_cache_alloc(hk_inode_cachep, GFP_NOFS);
    if (!vi)
        return NULL;
    
    if (ENABLE_META_PACK(sb)) {
        vi->layout_type = HUNTER_MOUNT_META_PACK;
        vi->header = NULL;
    } else {
        vi->layout_type = ~HUNTER_MOUNT_META_PACK;
        vi->header = hk_alloc_hk_inode_info_header();
        if (!vi->header) {
            kmem_cache_free(hk_inode_cachep, vi);
            return NULL;
        }
    }

    atomic64_set(&vi->vfs_inode.i_version, 1);

    return &vi->vfs_inode;
}

static void hk_i_callback(struct rcu_head *head)
{
    struct inode *inode = container_of(head, struct inode, i_rcu);
    struct hk_inode_info *vi = HK_I(inode);

    hk_dbg_verbose("%s: ino %lu\n", __func__, inode->i_ino);
    if (vi->layout_type != HUNTER_MOUNT_META_PACK) {
        hk_free_hk_inode_info_header(vi->header);
    }
    kmem_cache_free(hk_inode_cachep, vi);
}

static void hk_destroy_inode(struct inode *inode)
{
    hk_dbgv("%s: %lu\n", __func__, inode->i_ino);
    call_rcu(&inode->i_rcu, hk_i_callback);
}

static void init_once(void *foo)
{
    struct hk_inode_info *vi = foo;

    inode_init_once(&vi->vfs_inode);
}

static int __init init_inodecache(void)
{
    hk_inode_cachep = kmem_cache_create("hk_inode_cache",
                                        sizeof(struct hk_inode_info),
                                        0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), init_once);
    if (hk_inode_cachep == NULL)
        return -ENOMEM;
    return 0;
}

static void destroy_inodecache(void)
{
    /*
     * Make sure all delayed rcu free inodes are flushed before
     * we destroy cache.
     */
    rcu_barrier();
    if (hk_inode_cachep) {
        kmem_cache_destroy(hk_inode_cachep);
        hk_inode_cachep = NULL;
    }
}

/* FIXME: should the following variable be one per hk instance? */
unsigned int hk_dbgmask;

void hk_error_mng(struct super_block *sb, const char *fmt, ...)
{
    va_list args;

    printk(KERN_CRIT "hk error: ");
    va_start(args, fmt);
    vprintk(fmt, args);
    va_end(args);

    if (test_opt(sb, ERRORS_PANIC))
        panic("hk: panic from previous error\n");
    if (test_opt(sb, ERRORS_RO)) {
        printk(KERN_CRIT "hk err: remounting filesystem read-only");
        sb->s_flags |= MS_RDONLY;
    }
}

static void hk_set_blocksize(struct super_block *sb, unsigned long size)
{
    int bits;

    bits = fls(size) - 1;
    sb->s_blocksize_bits = bits;
    sb->s_blocksize = (1 << bits);
}

static int hk_get_nvmm_info(struct super_block *sb,
                            struct hk_sb_info *sbi)
{
    void *virt_addr = NULL;
    pfn_t __pfn_t;
    long size;
    struct dax_device *dax_dev;
    int ret;

    ret = bdev_dax_supported(sb->s_bdev, PAGE_SIZE);
    hk_dbg_verbose("%s: dax_supported = %d; bdev->super=0x%p",
                   __func__, ret, sb->s_bdev->bd_super);
    if (!ret) {
        hk_err(sb, "device does not support DAX\n");
        return -EINVAL;
    }

    sbi->s_bdev = sb->s_bdev;

    dax_dev = fs_dax_get_by_host(sb->s_bdev->bd_disk->disk_name);
    if (!dax_dev) {
        hk_err(sb, "Couldn't retrieve DAX device.\n");
        return -EINVAL;
    }
    sbi->s_dax_dev = dax_dev;

    size = PAGE_SIZE * dax_direct_access(sbi->s_dax_dev, 0, LONG_MAX / PAGE_SIZE,
                                         &virt_addr, &__pfn_t);
    if (size <= 0) {
        hk_err(sb, "direct_access failed\n");
        return -EINVAL;
    }

#ifdef ENABLE_GC_TEST_MODE
    size = EMU_PMEM_SIZE_GB * 1024 * 1024 * 1024;
#endif

    sbi->virt_addr = virt_addr;
    if (!sbi->virt_addr) {
        hk_err(sb, "ioremap of the hk image failed(1)\n");
        return -EINVAL;
    }

    sbi->phys_addr = pfn_t_to_pfn(__pfn_t) << PAGE_SHIFT;
    sbi->initsize = size;

    hk_dbg("%s: dev %s, phys_addr 0x%llx, virt_addr 0x%lx - %lx, size %ld\n",
           __func__, sbi->s_bdev->bd_disk->disk_name,
           sbi->phys_addr, (unsigned long)sbi->virt_addr, (unsigned long)(sbi->virt_addr + sbi->initsize),
           sbi->initsize);

    return 0;
}

static loff_t hk_max_size(int bits)
{
    loff_t res;

    res = (1ULL << 63) - 1;

    if (res > MAX_LFS_FILESIZE)
        res = MAX_LFS_FILESIZE;

    hk_dbg_verbose("max file size %llu bytes\n", res);
    return res;
}

enum {
    Opt_bpi,
    Opt_init,
    Opt_mode,
    Opt_uid,
    Opt_gid,
    Opt_dax,
    Opt_meta_async,
    Opt_meta_local,
    Opt_meta_lfs,
    Opt_meta_pack,
    Opt_history_w,
    Opt_wprotect,
    Opt_err_cont,
    Opt_err_panic,
    Opt_err_ro,
    Opt_dbgmask,
    Opt_err
};

static const match_table_t tokens = {
    {Opt_bpi, "bpi=%u"},
    {Opt_init, "init"},
    {Opt_mode, "mode=%o"},
    {Opt_uid, "uid=%u"},
    {Opt_gid, "gid=%u"},
    {Opt_dax, "dax"},
    {Opt_meta_async, "meta_async=%u"},
    {Opt_meta_local, "meta_local"},
    {Opt_meta_lfs, "meta_lfs"},
    {Opt_meta_pack, "meta_pack"},
    {Opt_history_w, "history_w"},
    {Opt_wprotect, "wprotect"},
    {Opt_err_cont, "errors=continue"},
    {Opt_err_panic, "errors=panic"},
    {Opt_err_ro, "errors=remount-ro"},
    {Opt_dbgmask, "dbgmask=%u"},
    {Opt_err, NULL},
};

static int hk_parse_options(char *options, struct hk_sb_info *sbi,
                            bool remount)
{
    char *p;
    substring_t args[MAX_OPT_ARGS];
    int option;
    kuid_t uid;
    struct super_block *sb = sbi->sb;

    if (!options)
        return 0;

    while ((p = strsep(&options, ",")) != NULL) {
        int token;

        if (!*p)
            continue;

        token = match_token(p, tokens, args);
        switch (token) {
        case Opt_uid:
            if (match_int(&args[0], &option))
                goto bad_val;
            uid = make_kuid(current_user_ns(), option);
            if (remount && !uid_eq(sbi->uid, uid))
                goto bad_opt;
            sbi->uid = uid;
            break;
        case Opt_gid:
            if (match_int(&args[0], &option))
                goto bad_val;
            sbi->gid = make_kgid(current_user_ns(), option);
            break;
        case Opt_mode:
            if (match_octal(&args[0], &option))
                goto bad_val;
            sbi->mode = option & 01777U;
            break;
        case Opt_init:
            if (remount)
                goto bad_opt;
            set_opt(sbi->s_mount_opt, FORMAT);
            break;
        case Opt_err_panic:
            clear_opt(sbi->s_mount_opt, ERRORS_CONT);
            clear_opt(sbi->s_mount_opt, ERRORS_RO);
            set_opt(sbi->s_mount_opt, ERRORS_PANIC);
            break;
        case Opt_err_ro:
            clear_opt(sbi->s_mount_opt, ERRORS_CONT);
            clear_opt(sbi->s_mount_opt, ERRORS_PANIC);
            set_opt(sbi->s_mount_opt, ERRORS_RO);
            break;
        case Opt_err_cont:
            clear_opt(sbi->s_mount_opt, ERRORS_RO);
            clear_opt(sbi->s_mount_opt, ERRORS_PANIC);
            set_opt(sbi->s_mount_opt, ERRORS_CONT);
            break;
        case Opt_dax:
            set_opt(sbi->s_mount_opt, DAX);
            break;
        case Opt_meta_async:
            if (match_int(&args[0], &option))
                goto bad_val;
            sbi->wake_up_interval = option;
            set_opt(sbi->s_mount_opt, META_ASYNC);
            break;
        case Opt_meta_local:
            set_opt(sbi->s_mount_opt, META_LOCAL);
            break;
        case Opt_meta_lfs:
            set_opt(sbi->s_mount_opt, META_LFS);
            break;
        case Opt_meta_pack:
            set_opt(sbi->s_mount_opt, META_PACK);
            break;
        case Opt_history_w:
            set_opt(sbi->s_mount_opt, HISTORY_W);
            break;
        case Opt_wprotect:
            if (remount)
                goto bad_opt;
            set_opt(sbi->s_mount_opt, PROTECT);
            hk_info("hk: Enabling new Write Protection (CR0.WP)\n");
            break;
        case Opt_dbgmask:
            if (match_int(&args[0], &option))
                goto bad_val;
            hk_dbgmask = option;
            break;
        default: {
            goto bad_opt;
        }
        }
    }

    if (ENABLE_META_PACK(sb) && ENABLE_META_LOCAL(sb) || ENABLE_META_PACK(sb) && ENABLE_META_LFS(sb) 
    || ENABLE_META_LFS(sb) && ENABLE_META_LOCAL(sb)) {
        hk_warn("META* are mutually exclusive\n");
        goto bad_opt;
    }

    return 0;

bad_val:
    hk_info("Bad value '%s' for mount option '%s'\n", args[0].from,
            p);
    return -EINVAL;
bad_opt:
    hk_info("Bad mount option: \"%s\"\n", p);
    return -EINVAL;
}

// TODO: This minimal size should be recalculated
/* Make sure we have enough space */
static bool hk_check_size(struct super_block *sb, unsigned long size)
{
    unsigned long minimum_size;
    struct hk_sb_info *sbi = HK_SB(sb);

    /* space required for super block and root directory.*/
    minimum_size = HK_SB_SIZE(sbi);

    if (size < minimum_size)
        return false;

    return true;
}

static inline int hk_check_super_checksum(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    u32 crc = 0;

    // Check CRC but skip c_sum, which is the 4 bytes at the beginning
    crc = hk_crc32c(~0, (__u8 *)sbi->hk_sb + sizeof(__le32),
                    sizeof(struct hk_super_block) - sizeof(__le32) + sbi->hk_sb->s_private_data_len);

    if (sbi->hk_sb->s_sum == cpu_to_le32(crc)) {
        return 0;
    }
    else {
        hk_err(sb, "hk: Checksum failed for super block, crc=%u, expected=%u\n", crc, le32_to_cpu(sbi->hk_sb->s_sum));
        return 1;
    }
}

static inline void hk_update_mount_time(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    u64 mnt_write_time;

    mnt_write_time = (get_seconds() & 0xFFFFFFFF);
    mnt_write_time = mnt_write_time | (mnt_write_time << 32);

    sbi->hk_sb->s_mtime = cpu_to_le64(mnt_write_time);
    hk_update_super_crc(sb);

    hk_sync_super(sb);
}

static inline void hk_mount_over(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);

    sbi->hk_sb->s_valid_umount = cpu_to_le32(HK_INVALID_UMOUNT);
    hk_update_super_crc(sb);

    hk_sync_super(sb);

    hk_info("MAX_GAP_BLKS_PER_LAYOUT: %llu\n", HK_MAX_GAPS_INRAM);
}

static inline void hk_umount_over(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    
    if (ENABLE_META_PACK(sb)) {
        struct hk_pack_data *pd;
        pd = (struct hk_pack_data *)(sbi->hk_sb + sizeof(struct hk_super_block));
    } else {
        struct hk_normal_data *nd;
        nd = (struct hk_normal_data *)(sbi->hk_sb + sizeof(struct hk_super_block));
        nd->s_tstamp = sbi->norm_layout.tstamp;
    }
    sbi->hk_sb->s_valid_umount = cpu_to_le32(HK_VALID_UMOUNT);
    hk_update_super_crc(sb);

    hk_sync_super(sb);
}

static int hk_format_hunter(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_super_block *super, *super_redund;
    unsigned long irq_flags = 0;
    
    super = hk_get_super(sb, HUNTER_FIRST_SUPER_BLK);
    hk_memunlock_super(sb, HUNTER_FIRST_SUPER_BLK, &irq_flags);
    memset_nt((void *)super, 0, HK_SB_SIZE(sbi));
    hk_memlock_super(sb, HUNTER_FIRST_SUPER_BLK, &irq_flags);

    super_redund = hk_get_super(sb, HUNTER_SECOND_SUPER_BLK);
    hk_memunlock_super(sb, HUNTER_SECOND_SUPER_BLK, &irq_flags);
    memset_nt((void *)super_redund, 0, HK_SB_SIZE(sbi));
    hk_memlock_super(sb, HUNTER_SECOND_SUPER_BLK, &irq_flags);

    hk_format_meta(sb);       
}

extern void generate_packages(struct super_block *sb);

static struct hk_inode *hk_init(struct super_block *sb,
                                unsigned long size)
{
    unsigned long blocksize;
    struct hk_inode *root_pi, *pi;
    struct hk_sb_info *sbi = HK_SB(sb);
    int ret;
    u64 epoch_id;
    unsigned long irq_flags = 0;
    int cpuid;
    INIT_TIMING(init_time);

    HK_START_TIMING(new_init_t, init_time);
    hk_info("creating an empty hunter of size %lu\n", size);

    sbi->num_blocks = ((unsigned long)(size) >> PAGE_SHIFT);
    sbi->blocksize = blocksize = HK_PBLK_SZ(sbi);
    hk_set_blocksize(sb, blocksize);

    if (!hk_check_size(sb, size)) {
        hk_warn("Specified hk size too small 0x%lx.\n", size);
        return ERR_PTR(-EINVAL);
    }

    hk_dbgv("max file name len %d\n", (unsigned int)HK_NAME_LEN);

    hk_format_hunter(sb);

#ifndef CONFIG_PERCORE_IALLOCATOR
    hk_init_free_inode_list(sb, true);
#else
    for (cpuid = 0; cpuid < sbi->cpus; cpuid++) {
        hk_init_free_inode_list_percore(sb, cpuid, true);
    }
#endif

    sbi->hk_sb->s_size = cpu_to_le64(size);
    sbi->hk_sb->s_blocksize = cpu_to_le32(blocksize);
    sbi->hk_sb->s_magic = cpu_to_le32(HUNTER_SUPER_MAGIC);
    sbi->s_inodes_used_count = 0;
    hk_update_super_crc(sb);

    /* Flush In-DRAM superblock into NVM */
    hk_sync_super(sb);

    if (ENABLE_META_PACK(sb)) {
        in_pkg_param_t create_param;
        in_create_pkg_param_t in_create_param;
        out_pkg_param_t out_param;
        out_create_pkg_param_t out_create_param;
        
        inode_mgr_restore(sbi->inode_mgr, HK_ROOT_INO);
        in_create_param.create_type = CREATE_FOR_NORMAL;
        in_create_param.new_ino = HK_ROOT_INO;
        create_param.private = &in_create_param;
        out_param.private = &out_create_param;
        create_param.cur_pkg_addr = 0;
        create_param.bin = false;
        ret = create_new_inode_pkg(sbi, cpu_to_le16(sbi->mode | S_IFDIR), "/", sbi->pack_layout.rih, NULL, &create_param, &out_param);

        if (ret) {
            hk_err(sb, "Create root inode failed\n");
            return ERR_PTR(ret);
        }
        hk_info("Root Inode is initialized at %lx\n", get_pm_offset(sbi, out_param.addr));
    
        generate_packages(sb);
    } else {
        root_pi = hk_get_inode_by_ino(sb, HK_ROOT_INO);
        hk_dbgv("%s: Allocate root inode @ 0x%p\n", __func__, root_pi);

        hk_memunlock_inode(sb, root_pi, &irq_flags);
        root_pi->i_mode = cpu_to_le16(sbi->mode | S_IFDIR);
        root_pi->i_uid = cpu_to_le32(from_kuid(&init_user_ns, sbi->uid));
        root_pi->i_gid = cpu_to_le32(from_kgid(&init_user_ns, sbi->gid));
        root_pi->i_links_count = cpu_to_le16(2);
        root_pi->i_flags = 0;
        root_pi->i_size = cpu_to_le64(sb->s_blocksize);
        root_pi->i_atime = root_pi->i_mtime = root_pi->i_ctime = cpu_to_le32(get_seconds());
#ifndef CONFIG_PERCORE_IALLOCATOR
        inode_mgr_alloc(&sbi->inode_mgr, &root_pi->ino);
#else
        root_pi->ino = cpu_to_le64(0);
#endif
        root_pi->valid = 1;
        hk_memlock_inode(sb, root_pi, &irq_flags);

        /* We don't care the order */
        hk_flush_buffer(root_pi, sizeof(struct hk_inode), false);
        PERSISTENT_BARRIER();
    }

    HK_END_TIMING(new_init_t, init_time);
    hk_info("hk initialization finish\n");
    return root_pi;
}

static inline void set_default_opts(struct hk_sb_info *sbi)
{
    set_opt(sbi->s_mount_opt, HUGEIOREMAP);
    set_opt(sbi->s_mount_opt, ERRORS_CONT);
    sbi->cpus = num_online_cpus(); // TODO: num_online_cpus();
    hk_info("%d cpus online\n", sbi->cpus);
}

static void hk_root_check(struct super_block *sb, struct hk_inode *root_pi)
{
    if (!S_ISDIR(le16_to_cpu(root_pi->i_mode)))
        hk_warn("root is not a directory!\n");
}

/* Check super block magic and checksum */
static int hk_check_super(struct super_block *sb,
                          struct hk_super_block *ps)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    int rc;

    rc = memcpy_mcsafe(sbi->hk_sb, ps,
                       sizeof(struct hk_super_block));

    if (rc < 0)
        return rc;

    if (le32_to_cpu(sbi->hk_sb->s_magic) != HUNTER_SUPER_MAGIC)
        return -EIO;

    rc = memcpy_mcsafe((char *)sbi->hk_sb + sizeof(struct hk_super_block), 
                       (char *)ps + sizeof(struct hk_super_block),
                       HK_SB_SIZE(sbi) - sizeof(struct hk_super_block));
    if (rc < 0)
        return rc;

    if (hk_check_super_checksum(sb))
        return -EIO;

    return 0;
}

static int hk_check_integrity(struct super_block *sb, int n)
{
    struct hk_super_block *super = hk_get_super(sb, n);
    int rc;

    rc = hk_check_super(sb, super);
    if (rc < 0) {
        hk_err(sb, "Can't find a valid hunter partition\n");
        return rc;
    }

    return 0;
}

/* FIXME: these feilds might change when the system is running... */
static int hk_super_constants_init(struct hk_sb_info *sbi)
{
    struct super_block *sb = sbi->sb;
    u64 max_rg_size;
    int i;
    
    sbi->lblk_sz = PAGE_SIZE;
    if (ENABLE_META_PACK(sb)) {
        sbi->pblk_sz = PAGE_SIZE;
        sbi->m_addr = sbi->pack_layout.bm_start = _round_up((u64)sbi->virt_addr + HUNTER_SUPER_BLKS * HK_SB_SIZE(sbi), PAGE_SIZE);
        sbi->pack_layout.tl_per_type_bm_reserved_blks = (_round_up(((sbi->initsize >> PAGE_SHIFT) >> 3), PAGE_SIZE) >> PAGE_SHIFT);
        sbi->m_size = sbi->pack_layout.bm_size = hk_get_bm_size(sb);
        sbi->pack_layout.fs_start = _round_up(sbi->m_addr + sbi->m_size, PAGE_SIZE);
    } else {
        sbi->pblk_sz = ENABLE_META_LOCAL(sb) ? PAGE_SIZE : PAGE_SIZE + sizeof(struct hk_header);

        /* Layout Related */
        sbi->m_addr = _round_up((u64)sbi->virt_addr + HUNTER_SUPER_BLKS * HK_SB_SIZE(sbi), PAGE_SIZE);

        /* Build Inode Table */
        sbi->norm_layout.ino_tab_addr = sbi->m_addr;
        sbi->norm_layout.ino_tab_slots = HK_NUM_INO;
        sbi->norm_layout.ino_tab_size = _round_up(sbi->norm_layout.ino_tab_slots * sizeof(struct hk_inode), PAGE_SIZE);

        /* Build Summary Header */
        sbi->norm_layout.sm_addr = sbi->norm_layout.ino_tab_addr + sbi->norm_layout.ino_tab_size;
        if (ENABLE_META_LOCAL(sb)) {
            sbi->norm_layout.sm_slots = sbi->initsize / HK_PBLK_SZ(sbi);
            sbi->norm_layout.sm_size = _round_up(sbi->norm_layout.sm_slots * sizeof(struct hk_header), PAGE_SIZE);
        } else {
            sbi->norm_layout.sm_slots = 0;
            sbi->norm_layout.sm_size = 0;
        }

        /* Build Journal */
        sbi->norm_layout.j_addr = sbi->norm_layout.sm_addr + sbi->norm_layout.sm_size;
        sbi->norm_layout.j_slots = sbi->cpus * HK_PERCORE_JSLOTS;
        sbi->norm_layout.j_size = _round_up(sbi->norm_layout.j_slots * HK_JOURNAL_SIZE, PAGE_SIZE);
        sbi->norm_layout.j_locks = kcalloc(sbi->norm_layout.j_slots, sizeof(struct mutex), GFP_KERNEL);
        for (i = 0; i < sbi->norm_layout.j_slots; i++)
            mutex_init(&sbi->norm_layout.j_locks[i]);

        /* Build Meta Region */
        sbi->norm_layout.rg_addr = sbi->norm_layout.j_addr + sbi->norm_layout.j_size;
        sbi->norm_layout.rg_slots = HK_RG_SLOTS > HK_NUM_INO ? HK_NUM_INO : HK_RG_SLOTS;
        sbi->pack_layout.obj_mgr = _round_up(sbi->norm_layout.rg_slots * sizeof(struct hk_mregion), PAGE_SIZE);

        /* Calc Meta Size and Data Size */
        sbi->m_size = _round_up(sbi->norm_layout.rg_addr - sbi->m_addr + sbi->pack_layout.obj_mgr, PAGE_SIZE);
    }

    sbi->d_addr = _round_up(sbi->m_addr + sbi->m_size, PAGE_SIZE);
    sbi->d_size = sbi->initsize - (sbi->d_addr - (u64)sbi->virt_addr);
    sbi->d_blks = sbi->d_size / HK_PBLK_SZ(sbi);

    /* write control */
    atomic64_set(&sbi->num_writers, 0);
    
    /* read ahead mechanisms */
    sbi->ra_win = HK_READAHEAD_WINDOW;
    atomic64_set(&sbi->num_readers, 0);

    hk_dbgv("%s: meta addr: %llx, meta_size: %llx; data addr: %llx\n", __func__, sbi->m_addr, sbi->m_size, sbi->d_addr);
    return 0;
}

static int hk_super_constants_init_exit(struct hk_sb_info *sbi)
{
    if (ENABLE_META_LOCAL(sbi->sb))
        kfree(sbi->norm_layout.j_locks);
    return 0;
}

static int hk_features_init(struct hk_sb_info *sbi)
{
    int i, ret = 0;
    struct super_block *sb = sbi->sb;

    /* Inode List Related */
    sbi->inode_mgr = (struct inode_mgr *)kmalloc(sizeof(struct inode_mgr), GFP_KERNEL);
    if (!sbi->inode_mgr)
        return -ENOMEM;
    
    ret = inode_mgr_init(sbi, sbi->inode_mgr);
    if (ret < 0)
        return ret;
    
    if (ENABLE_META_PACK(sb)) {
        /* zero out vtail */
        atomic64_and(0, &sbi->pack_layout.vtail);
        sbi->pack_layout.obj_mgr = (struct obj_mgr *)kmalloc(sizeof(struct obj_mgr), GFP_KERNEL);
        if (!sbi->pack_layout.obj_mgr) {
            inode_mgr_destroy(sbi->inode_mgr);
            return -ENOMEM;
        }
        ret = obj_mgr_init(sbi, sbi->cpus, sbi->pack_layout.obj_mgr);
        if (ret) {
            inode_mgr_destroy(sbi->inode_mgr);
            return ret;
        }
    } else
    {    
        sbi->norm_layout.irange_locks = kcalloc(sbi->cpus, sizeof(struct mutex), GFP_KERNEL);
        for (i = 0; i < sbi->cpus; i++)
            mutex_init(&sbi->norm_layout.irange_locks[i]);
        /* Version Related */
        sbi->norm_layout.tstamp = 0;
        spin_lock_init(&sbi->norm_layout.ts_lock);
    }

    /* Background Commit Related */
    if (ENABLE_META_ASYNC(sb)) {
        sbi->cq = hk_init_cmt_queue(sb, 4);
        if (!sbi->cq)
            return -ENOMEM;
    }

    if (ENABLE_HISTORY_W(sb)) {
        /* Dynamic Workload */
        hk_dw_init(&sbi->dw, HK_LINIX_SLOTS);
    }

    return 0;
}

static int hk_features_exit(struct hk_sb_info *sbi)
{
    struct super_block *sb = sbi->sb;

    if (ENABLE_META_PACK(sb)) {
        obj_mgr_destroy(sbi->pack_layout.obj_mgr);
    } else {
        kfree(sbi->norm_layout.irange_locks);
    }

    inode_mgr_destroy(sbi->inode_mgr);

    return 0;
}

extern void * __must_check kvrealloc(void* old_ptr, size_t old_size, size_t new_size, gfp_t mode);

static int hk_misc_init(struct hk_sb_info *sbi)
{
    struct super_block *sb = sbi->sb;
    void *hk_sb;

    sbi->hk_sb->s_private_data = sizeof(struct hk_super_block);
    sbi->pack_layout.rih = NULL;
    if (ENABLE_META_PACK(sb)) {
        sbi->hk_sb->s_private_data_len = sizeof(struct hk_pack_data);
        if (sbi->s_mount_opt & HUNTER_MOUNT_FORMAT) {
            sbi->pack_layout.rih = hk_alloc_hk_inode_info_header();
            if (!sbi->pack_layout.rih)
                return -ENOMEM;
            /* do not init dyn array */
            hk_init_header(sb, sbi->pack_layout.rih, S_IFPSEUDO);
            /* reinit modes */
            sbi->pack_layout.rih->i_mode = cpu_to_le16(sbi->mode | S_IFDIR);
            sbi->pack_layout.rih->i_uid = cpu_to_le32(from_kuid(&init_user_ns, sbi->uid));
            sbi->pack_layout.rih->i_gid= cpu_to_le32(from_kgid(&init_user_ns, sbi->gid));
        }
    } else {
        sbi->hk_sb->s_private_data_len = sizeof(struct hk_normal_data);
    }
    
    hk_sb = kvrealloc(sbi->hk_sb, sizeof(struct hk_super_block), HK_SB_SIZE(sbi), GFP_KERNEL);
    if (!hk_sb)
        return -ENOMEM;
    sbi->hk_sb = hk_sb;
    
    hk_info("super block size is extended from %lu to %lu\n", sizeof(struct hk_super_block), HK_SB_SIZE(sbi));
    /* Zero out the private data */
    memset(((char *)hk_sb) + sizeof(struct hk_super_block), 0, HK_SB_SIZE(sbi) - sizeof(struct hk_super_block));

    return 0;
}

static int hk_misc_exit(struct hk_sb_info *sbi)
{
    return 0;
}

void hk_backup_super(struct hk_sb_info *sbi, u32 orig_super_blk, u32 back_super_blk)
{
    struct hk_super_block *super, *bak_super;
    super = sbi->virt_addr + (orig_super_blk * HK_SB_SIZE(sbi));
    bak_super = sbi->virt_addr + (back_super_blk * HK_SB_SIZE(sbi));
    memcpy_to_pmem_nocache(bak_super, super, HK_SB_SIZE(sbi));
}

static int hk_fill_super(struct super_block *sb, void *data, int silent)
{
    struct hk_inode *root_pi;
    struct hk_sb_info *sbi = NULL;
    struct inode *root_i = NULL;
    unsigned long blocksize;
    u32 random = 0;
    int retval = -EINVAL;

    INIT_TIMING(mount_time);
    HK_START_TIMING(mount_t, mount_time);

    sbi = kzalloc(sizeof(struct hk_sb_info), GFP_KERNEL);
    if (!sbi)
        return -ENOMEM;
    sbi->hk_sb = kzalloc(sizeof(struct hk_super_block), GFP_KERNEL);
    if (!sbi->hk_sb) {
        kfree(sbi);
        return -ENOMEM;
    }

    sb->s_fs_info = sbi;
    sbi->sb = sb;

    set_default_opts(sbi);

    if (sbi->cpus > POSSIBLE_MAX_CPU) {
        hk_err(sb, "hunter does't support more than " __stringify(POSSIBLE_MAX_CPU) " cpus for now.\n");
        goto out;
    }

    retval = hk_get_nvmm_info(sb, sbi);
    if (retval) {
        hk_err(sb, "%s: Failed to get nvmm info.",
               __func__);
        goto out;
    }

    get_random_bytes(&random, sizeof(u32));
    atomic_set(&sbi->next_generation, random);

    /* Init with default values */
    sbi->mode = (0755);
    sbi->uid = current_fsuid();
    sbi->gid = current_fsgid();
    set_opt(sbi->s_mount_opt, HUGEIOREMAP);

    mutex_init(&sbi->vma_mutex);
    INIT_LIST_HEAD(&sbi->mmap_sih_list);

    mutex_init(&sbi->s_lock);

    retval = hk_parse_options(data, sbi, 0);
    if (retval) {
        hk_err(sb, "%s: Failed to parse hk command line options.",
               __func__);
        goto out;
    }

    hk_super_constants_init(sbi);

    /* init some misc structures */
    hk_misc_init(sbi);

    /* init structures (e.g., inode manager) by CONFIG accordingly */    
    hk_features_init(sbi);

    hk_layouts_init(sbi, sbi->cpus);

    hk_sysfs_init(sb);

    hk_info("measure timing %d, wprotect %d\n", measure_timing, wprotect);

    /* Init a new hk instance */
    if (sbi->s_mount_opt & HUNTER_MOUNT_FORMAT) {
        root_pi = hk_init(sb, sbi->initsize);
        retval = -ENOMEM;
        if (IS_ERR(root_pi)) {
            hk_err(sb, "%s: root_pi error.",
                   __func__);

            goto out;
        }
        goto setup_sb;
    }

    hk_dbg_verbose("Start checking physical address 0x%016llx for hunter image\n",
                   (u64)sbi->phys_addr);

    if (hk_check_integrity(sb, HUNTER_FIRST_SUPER_BLK) < 0) {
        if (hk_check_integrity(sb, HUNTER_SECOND_SUPER_BLK) < 0) {
            retval = -EINVAL;
            hk_dbg("Memory contains invalid hunter %x:%x\n",
                le32_to_cpu(sbi->hk_sb->s_magic), HUNTER_SUPER_MAGIC);
            goto out;
        }
        hk_backup_super(sbi, HUNTER_SECOND_SUPER_BLK, HUNTER_FIRST_SUPER_BLK);
    }
    hk_backup_super(sbi, HUNTER_FIRST_SUPER_BLK, HUNTER_SECOND_SUPER_BLK);

    blocksize = le32_to_cpu(sbi->hk_sb->s_blocksize);
    hk_set_blocksize(sb, blocksize);

    hk_dbg_verbose("blocksize %lu\n", blocksize);

    /* TODO: We shall do the check later, after hunter_recovery */
    // /* Read the root inode */
    // root_pi = hk_get_inode_by_ino(sb, HK_ROOT_INO);
    // /* Check that the root inode is in a sane state */
    // hk_root_check(sb, root_pi);

    /* Set it all up.. */
setup_sb:
    sb->s_magic = le32_to_cpu(sbi->hk_sb->s_magic);
    sb->s_op = &hk_sops;              
    sb->s_export_op = &hk_export_ops; 
    sb->s_maxbytes = hk_max_size(sb->s_blocksize_bits);
    sb->s_time_gran = 1000000000; // 1 second.
    sb->s_xattr = NULL;
    sb->s_flags |= MS_NOSEC;

    /* If the FS was not formatted on this mount, scan the meta-data after
     * truncate list has been processed
     */
    if ((sbi->s_mount_opt & HUNTER_MOUNT_FORMAT) == 0) {
        retval = hk_recovery(sb);
        if (retval < 0) {
            hk_err(sb, "%s: hk recovery failed with return code %d\n",
                   __func__, retval);
            goto out;
        }
    }

    root_i = hk_iget(sb, HK_ROOT_INO);
    if (IS_ERR(root_i)) {
        retval = PTR_ERR(root_i);
        hk_err(sb, "%s: failed to get root inode",
               __func__);

        goto out;
    }

    sb->s_root = d_make_root(root_i);
    if (!sb->s_root) {
        hk_err(sb, "get hk root inode failed\n");
        retval = -ENOMEM;
        goto out;
    }

    if (!(sb->s_flags & MS_RDONLY))
        hk_update_mount_time(sb);

    hk_mount_over(sb);

#if 0
#ifdef CONFIG_ENABLE_EQUALIZER
    hk_start_equalizer(sb);
#endif
#endif

    if (ENABLE_META_ASYNC(sb)) {
        hk_start_cmt_workers(sb);
    }

    retval = 0;
    HK_END_TIMING(mount_t, mount_time);
    return retval;

out:
    hk_sysfs_exit(sb);

    hk_layouts_free(sbi);
    kfree(sbi->hk_sb);
    kfree(sbi);
    hk_dbg("%s failed: return %d\n", __func__, retval);
    return retval;
}

int hk_statfs(struct dentry *d, struct kstatfs *buf)
{
    struct super_block *sb = d->d_sb;
    struct hk_sb_info *sbi = (struct hk_sb_info *)sb->s_fs_info;

    buf->f_type = HUNTER_SUPER_MAGIC;
    buf->f_bsize = sb->s_blocksize;

    buf->f_blocks = sbi->num_blocks;
    buf->f_bfree = buf->f_bavail = hk_count_free_blocks(sb);
    buf->f_files = HK_NUM_INO;
    buf->f_ffree = HK_NUM_INO - sbi->s_inodes_used_count;
    buf->f_namelen = HK_NAME_LEN;
    hk_dbg_verbose("hk_stats: total 4k free blocks 0x%llx\n",
                   buf->f_bfree);
    return 0;
}

static int hk_show_options(struct seq_file *seq, struct dentry *root)
{
    struct hk_sb_info *sbi = HK_SB(root->d_sb);
    
    if (sbi->mode != (0777 | S_ISVTX))
        seq_printf(seq, ",mode=%03o", sbi->mode);
    if (uid_valid(sbi->uid))
        seq_printf(seq, ",uid=%u", from_kuid(&init_user_ns, sbi->uid));
    if (gid_valid(sbi->gid))
        seq_printf(seq, ",gid=%u", from_kgid(&init_user_ns, sbi->gid));
    if (test_opt(root->d_sb, ERRORS_RO))
        seq_puts(seq, ",errors=remount-ro");
    if (test_opt(root->d_sb, ERRORS_PANIC))
        seq_puts(seq, ",errors=panic");
    /* memory protection disabled by default */
    if (test_opt(root->d_sb, PROTECT))
        seq_puts(seq, ",wprotect");

    return 0;
}

int hk_remount(struct super_block *sb, int *mntflags, char *data)
{
    unsigned long old_sb_flags;
    unsigned long old_mount_opt;
    struct hk_sb_info *sbi = HK_SB(sb);
    int ret = -EINVAL;

    /* Store the old options */
    mutex_lock(&sbi->s_lock);
    old_sb_flags = sb->s_flags;
    old_mount_opt = sbi->s_mount_opt;

    if (hk_parse_options(data, sbi, 1))
        goto restore_opt;

    sb->s_flags = (sb->s_flags & ~MS_POSIXACL) |
                  ((sbi->s_mount_opt & HUNTER_MOUNT_POSIX_ACL) ? MS_POSIXACL : 0);

    if ((*mntflags & MS_RDONLY) != (sb->s_flags & MS_RDONLY))
        hk_update_mount_time(sb);

    mutex_unlock(&sbi->s_lock);
    ret = 0;
    return ret;

restore_opt:
    sb->s_flags = old_sb_flags;
    sbi->s_mount_opt = old_mount_opt;
    mutex_unlock(&sbi->s_lock);
    return ret;
}

static void hk_put_super(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_super_block *super;
    int i;

#if 0
#ifdef CONFIG_ENABLE_EQUALIZER
    hk_terminal_equalizer(sb);
#endif
#endif

    if (ENABLE_META_ASYNC(sb)) {
        hk_stop_cmt_workers(sb);
        hk_flush_cmt_queue(sb);
        /* destory cmt queue */
        hk_free_cmt_queue(sbi->cq);
        hk_stablisze_meta(sb);
    }

    /* It's unmount time, so unmap the hk memory */
    if (sbi->virt_addr) {
        if (!ENABLE_META_PACK(sb)) {
            hk_save_regions(sb);
        }
        hk_save_layouts(sb);
        hk_umount_over(sb);
        sbi->virt_addr = NULL;
    }

    hk_super_constants_init_exit(sbi);
    hk_misc_exit(sbi);
    hk_layouts_free(sbi);
    hk_features_exit(sbi);
    hk_sysfs_exit(sb);

    hk_dbgmask = 0;

    kvfree(sbi->hk_sb);
    kfree(sbi);
    sb->s_fs_info = NULL;
}

/*
 * the super block writes are all done "on the fly", so the
 * super block is never in a "dirty" state, so there's no need
 * for write_super.
 */
static struct super_operations hk_sops = {
    .alloc_inode = hk_alloc_inode,
    .destroy_inode = hk_destroy_inode,
    .write_inode = hk_write_inode, 
    .dirty_inode = NULL,           /* TODO: Not support yet */
    .evict_inode = hk_evict_inode, 
    .put_super = hk_put_super,
    .statfs = hk_statfs,
    .remount_fs = hk_remount,
    .show_options = hk_show_options,
};

static struct dentry *hk_mount(struct file_system_type *fs_type,
                               int flags, const char *dev_name, void *data)
{
    return mount_bdev(fs_type, flags, dev_name, data, hk_fill_super);
}

static struct file_system_type hk_fs_type = {
    .owner = THIS_MODULE,
    .name = "HUNTER",
    .mount = hk_mount,
    .kill_sb = kill_block_super,
};

static struct inode *hk_nfs_get_inode(struct super_block *sb,
                                      u64 ino, u32 generation)
{
    struct inode *inode;

    if (ino < HK_ROOT_INO)
        return ERR_PTR(-ESTALE);

    if (ino > UINT_MAX)
        return ERR_PTR(-ESTALE);

    inode = hk_iget(sb, ino);
    if (IS_ERR(inode))
        return ERR_CAST(inode);

    if (generation && inode->i_generation != generation) {
        /* we didn't find the right inode.. */
        iput(inode);
        return ERR_PTR(-ESTALE);
    }

    return inode;
}

static struct dentry *hk_fh_to_dentry(struct super_block *sb,
                                      struct fid *fid, int fh_len,
                                      int fh_type)
{
    return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
                                hk_nfs_get_inode);
}

static struct dentry *hk_fh_to_parent(struct super_block *sb,
                                      struct fid *fid, int fh_len,
                                      int fh_type)
{
    return generic_fh_to_parent(sb, fid, fh_len, fh_type,
                                hk_nfs_get_inode);
}

static const struct export_operations hk_export_ops = {
    .fh_to_dentry = hk_fh_to_dentry,
    .fh_to_parent = hk_fh_to_parent,
    .get_parent = hk_get_parent,
};

void hk_destory_slab_caches(void)
{
    destroy_hk_range_node_cache();
    destroy_hk_dentry_info_cache();
    destroy_hk_cmt_info_cache();
    destroy_obj_ref_inode_cache();
    destroy_obj_ref_attr_cache();
    destroy_obj_ref_dentry_cache();
    destroy_obj_ref_data_cache();
    destroy_claim_req_cache();
    destroy_hk_inode_info_header_cache();
    destroy_tl_node_cache();
}

static int __init hk_create_slab_caches(void)
{
    int rc = 0;

    rc = init_hk_range_node_cache();
    if (rc)
        goto out;

    rc = init_hk_dentry_info_cache();
    if (rc)
        goto out;

    rc = init_hk_cmt_info_cache();
    if (rc)
        goto out;
    
    /* init caches */
    rc = init_obj_ref_inode_cache();
    if (rc)
        goto out;
    
    rc = init_obj_ref_attr_cache();
    if (rc)
        goto out;
    
    rc = init_obj_ref_dentry_cache();
    if (rc)
        goto out;
    
    rc = init_obj_ref_data_cache();
    if (rc)
        goto out;

    rc = init_claim_req_cache();
    if (rc)
        goto out;

    rc = init_hk_inode_info_header_cache();
    if (rc)
        goto out;

    rc = init_tl_node_cache();
    if (rc)
        goto out;

out:
    return rc;
}

static int __init init_hk_fs(void)
{
    int rc = 0;
    INIT_TIMING(init_time);

    HK_START_TIMING(init_t, init_time);
    if (arch_has_clwb())
        support_clwb = 1;

    hk_info("Arch new instructions support: CLWB %s\n",
            support_clwb ? "YES" : "NO");

    hk_proc_root = proc_mkdir(proc_dirname, NULL);
    rc = hk_create_slab_caches();
    if (rc)
        goto out1;

    rc = init_inodecache();
    if (rc)
        goto out2;

    rc = register_filesystem(&hk_fs_type);
    if (rc)
        goto out2;

    HK_END_TIMING(init_t, init_time);
    return 0;

out2:
    destroy_inodecache();
out1:
    hk_destory_slab_caches();
    return rc;
}

static void __exit exit_hk_fs(void)
{
    unregister_filesystem(&hk_fs_type);
    remove_proc_entry(proc_dirname, NULL);
    destroy_inodecache();
    hk_destory_slab_caches();
}

MODULE_AUTHOR("Yanqi Pan <deadpoolmine@qq.com>");
MODULE_DESCRIPTION("HUNTER: An Exact Write-ONCE PM File System with Memory Considerations");
MODULE_LICENSE("GPL");

module_init(init_hk_fs)
module_exit(exit_hk_fs)
