/*
 * BRIEF DESCRIPTION
 *
 * Memory protection definitions for the WOFS filesystem.
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

#ifndef _WOFS_WPROTECT_H
#define _WOFS_WPROTECT_H

#include "wofs.h"

extern void wofs_error_mng(struct super_block *sb, const char *fmt, ...);

static inline int wofs_range_check(struct super_block *sb, void *p,
					 			 unsigned long len)
{
	struct wofs_sb_info *sbi = WOFS_SB(sb);

	if (p < sbi->virt_addr ||
			p + len > sbi->virt_addr + sbi->initsize) {
		wofs_err(sb, "access pmem out of range: pmem range 0x%lx - 0x%lx, "
				"access range 0x%lx - 0x%lx\n",
				(unsigned long)sbi->virt_addr,
				(unsigned long)(sbi->virt_addr + sbi->initsize),
				(unsigned long)p, (unsigned long)(p + len));
		dump_stack();
		return -EINVAL;
	}

	return 0;
}

static inline void wprotect_disable(void)
{
	unsigned long cr0_val;

	cr0_val = read_cr0();
	cr0_val &= (~X86_CR0_WP);
	write_cr0(cr0_val);
}

static inline void wprotect_enable(void)
{
	unsigned long cr0_val;

	cr0_val = read_cr0();
	cr0_val |= X86_CR0_WP;
	write_cr0(cr0_val);
}

/* FIXME: Assumes that we are always called in the right order.
 * wofs_writeable(vaddr, size, 1);
 * wofs_writeable(vaddr, size, 0);
 */
static inline int
wofs_writeable(void *vaddr, unsigned long size, int rw, unsigned long *flags)
{
	INIT_TIMING(wprotect_time);

	WOFS_START_TIMING(wprotect_t, wprotect_time);
	if (rw) {
		local_irq_save(*flags);
		wprotect_disable();
	} else {
		wprotect_enable();
		local_irq_restore(*flags);
	}
	WOFS_END_TIMING(wprotect_t, wprotect_time);
	return 0;
}

extern int wprotect;

static inline int wofs_is_protected(struct super_block *sb)
{
	struct wofs_sb_info *sbi = (struct wofs_sb_info *)sb->s_fs_info;

	if (wprotect)
		return wprotect;

	return sbi->s_mount_opt & WOFS_MOUNT_PROTECT;
}

static inline int wofs_is_wprotected(struct super_block *sb)
{
	return wofs_is_protected(sb);
}

static inline void
__wofs_memunlock_range(void *p, unsigned long len, unsigned long *flags)
{
	/*
	 * NOTE: Ideally we should lock all the kernel to be memory safe
	 * and avoid to write in the protected memory,
	 * obviously it's not possible, so we only serialize
	 * the operations at fs level. We can't disable the interrupts
	 * because we could have a deadlock in this path.
	 */
	wofs_writeable(p, len, 1, flags);
}

static inline void
__wofs_memlock_range(void *p, unsigned long len, unsigned long *flags)
{
	wofs_writeable(p, len, 0, flags);
}

static inline void wofs_memunlock_range(struct super_block *sb, void *p,
					 				  unsigned long len, unsigned long *flags)
{
	// if (wofs_range_check(sb, p, len))
	// 	return;
	if (wofs_is_protected(sb))
		__wofs_memunlock_range(p, len, flags);
}

static inline void wofs_memlock_range(struct super_block *sb, void *p,
				       				unsigned long len, unsigned long *flags)
{
	if (wofs_is_protected(sb))
		__wofs_memlock_range(p, len, flags);
}

static inline void wofs_memunlock_super(struct super_block *sb, int n, unsigned long *flags)
{
	struct wofs_super_block *ps = wofs_get_super(sb, n);
	struct wofs_sb_info *sbi = WOFS_SB(sb);

	if (wofs_is_protected(sb))
		__wofs_memunlock_range(ps, WOFS_SB_SIZE(sbi), flags);
}

static inline void wofs_memlock_super(struct super_block *sb, int n, unsigned long *flags)
{
	struct wofs_super_block *ps = wofs_get_super(sb, n);
	struct wofs_sb_info *sbi = WOFS_SB(sb);

	if (wofs_is_protected(sb))
		__wofs_memlock_range(ps, WOFS_SB_SIZE(sbi), flags);
}

static inline void wofs_memunlock_hdr(struct super_block *sb, 
									struct wofs_header *hdr, unsigned long *flags)
{
	if (wofs_range_check(sb, hdr, sizeof(struct wofs_header)))
		return;

	if (wofs_is_protected(sb))
		__wofs_memunlock_range(hdr, sizeof(struct wofs_header), flags);
}

static inline void wofs_memlock_hdr(struct super_block *sb,
				       			  struct wofs_header *hdr, unsigned long *flags)
{
	if (wofs_is_protected(sb))
		__wofs_memlock_range(hdr, sizeof(struct wofs_header), flags);
}

static inline void wofs_memunlock_mregion(struct super_block *sb, 
									struct wofs_mregion *rg, unsigned long *flags)
{
	if (wofs_range_check(sb, rg, sizeof(struct wofs_mregion)))
		return;

	if (wofs_is_protected(sb))
		__wofs_memunlock_range(rg, sizeof(struct wofs_mregion), flags);
}

static inline void wofs_memlock_mregion(struct super_block *sb,
				       			  struct wofs_mregion *rg, unsigned long *flags)
{
	if (wofs_is_protected(sb))
		__wofs_memlock_range(rg, sizeof(struct wofs_mregion), flags);
}

static inline void wofs_memunlock_journal(struct super_block *sb, 
									struct wofs_journal *jnl, unsigned long *flags)
{
	if (wofs_range_check(sb, jnl, sizeof(struct wofs_journal)))
		return;

	if (wofs_is_protected(sb))
		__wofs_memunlock_range(jnl, sizeof(struct wofs_journal), flags);
}

static inline void wofs_memlock_journal(struct super_block *sb,
				       			  struct wofs_journal *jnl, unsigned long *flags)
{
	if (wofs_is_protected(sb))
		__wofs_memlock_range(jnl, sizeof(struct wofs_journal), flags);
}


static inline void wofs_memunlock_dentry(struct super_block *sb, 
									   struct wofs_dentry *direntry, unsigned long *flags)
{
	if (wofs_range_check(sb, direntry, sizeof(struct wofs_dentry)))
		return;

	if (wofs_is_protected(sb))
		__wofs_memunlock_range(direntry, sizeof(struct wofs_dentry), flags);
}

static inline void wofs_memlock_dentry(struct super_block *sb,
				       			     struct wofs_dentry *direntry, unsigned long *flags)
{
	if (wofs_is_protected(sb))
		__wofs_memlock_range(direntry, sizeof(struct wofs_dentry), flags);
}

static inline void wofs_memunlock_all(struct super_block *sb, unsigned long *flags)
{
	struct wofs_sb_info *sbi = (struct wofs_sb_info *)sb->s_fs_info;
	if (wofs_is_protected(sb))
		__wofs_memunlock_range(sbi->virt_addr, sbi->initsize, flags);
}

static inline void wofs_memlock_all(struct super_block *sb, unsigned long *flags)
{
	struct wofs_sb_info *sbi = (struct wofs_sb_info *)sb->s_fs_info;
	if (wofs_is_protected(sb))
		__wofs_memlock_range(sbi->virt_addr, sbi->initsize, flags);
}

static inline void wofs_memunlock_inode(struct super_block *sb, 
									  struct wofs_inode *pi, unsigned long *flags)
{
	if (wofs_range_check(sb, pi, sizeof(struct wofs_inode)))
		return;

	if (wofs_is_protected(sb))
		__wofs_memunlock_range(pi, sizeof(struct wofs_inode), flags);
}

static inline void wofs_memlock_inode(struct super_block *sb,
				       struct wofs_inode *pi, unsigned long *flags)
{
	if (wofs_is_protected(sb))
		__wofs_memlock_range(pi, sizeof(struct wofs_inode), flags);
}

static inline void wofs_memunlock_block(struct super_block *sb, void *bp, unsigned long *flags)
{
	if (wofs_range_check(sb, bp, sb->s_blocksize))
		return;

	if (wofs_is_protected(sb))
		__wofs_memunlock_range(bp, sb->s_blocksize, flags);
}

static inline void wofs_memlock_block(struct super_block *sb, void *bp, unsigned long *flags)
{
	if (wofs_is_protected(sb))
		__wofs_memlock_range(bp, sb->s_blocksize, flags);
}

static inline void wofs_memunlock_bm(struct super_block *sb, u16 bmblk, unsigned long *flags)
{
	struct wofs_sb_info *sbi = WOFS_SB(sb);
	u64 addr = WOFS_BM_ADDR(sbi, bmblk);
	u64 size = BMBLK_SIZE(sbi);
	if (wofs_range_check(sb, addr, size))
		return;

	if (wofs_is_protected(sb))
		__wofs_memunlock_range(addr, size, flags);
}

static inline void wofs_memlock_bm(struct super_block *sb, u16 bmblk, unsigned long *flags)
{
	struct wofs_sb_info *sbi = WOFS_SB(sb);
	u64 addr = WOFS_BM_ADDR(sbi, bmblk);
	u64 size = BMBLK_SIZE(sbi);
	if (wofs_is_protected(sb))
		__wofs_memlock_range(addr, size, flags);
}


#endif /* _WOFS_WPROTECT_H */
