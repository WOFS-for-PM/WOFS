#ifndef _WOFS_H
#define _WOFS_H

#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/dax.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/backing-dev.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/radix-tree.h>
#include <linux/version.h>
#include <linux/kthread.h>
#include <linux/buffer_head.h>
#include <linux/uio.h>
#include <linux/iomap.h>
#include <linux/crc32c.h>
#include <asm/tlbflush.h>
#include <linux/version.h>
#include <linux/pfn_t.h>
#include <linux/pagevec.h>
#include <linux/uaccess.h>
#include <linux/falloc.h>
#include <asm/mman.h>
#include <linux/compat.h>
#include <linux/hashtable.h>
#include <linux/sched/signal.h>
#include <linux/libnvdimm.h>
#include "asm/fpu/api.h"

#define TRANS_ADDR_TO_OFS(sbi, addr)  (addr == 0 ? 0 : ((u64)(addr) - (u64)(sbi)->virt_addr))   
#define TRANS_OFS_TO_ADDR(sbi, ofs)   (ofs == 0 ? 0 : ((u64)(ofs) + (sbi)->virt_addr))
#define GET_ALIGNED_BLKNR(ofs_addr) ((ofs_addr) >> WOFS_BLK_SHIFT)

#define WOFS_VALID_UMOUNT     0xffffffff
#define WOFS_INVALID_UMOUNT   0x00000000

#define ENABLE_META_ASYNC(sb)	test_opt(sb, META_ASYNC)
#define ENABLE_META_LOCAL(sb)	test_opt(sb, META_LOCAL)
#define ENABLE_META_LFS(sb)		test_opt(sb, META_LFS)
#define ENABLE_META_PACK(sb)	test_opt(sb, META_PACK)
#define ENABLE_HISTORY_W(sb)	test_opt(sb, HISTORY_W)

/*
 * wofs inode flags
 *
 * WOFS_EOFBLOCKS_FL			 There are blocks allocated beyond eof
 */
#define WOFS_EOFBLOCKS_FL      0x20000000

/* Flags that should be inherited by new inodes from their parent. */
#define WOFS_FL_INHERITED (FS_SECRM_FL | FS_UNRM_FL | FS_COMPR_FL | \
						FS_SYNC_FL | FS_NODUMP_FL | FS_NOATIME_FL |	\
						FS_COMPRBLK_FL | FS_NOCOMP_FL | \
						FS_JOURNAL_DATA_FL | FS_NOTAIL_FL | FS_DIRSYNC_FL)
/* Flags that are appropriate for regular files (all but dir-specific ones). */
#define WOFS_REG_FLMASK 	(~(FS_DIRSYNC_FL | FS_TOPDIR_FL))
/* Flags that are appropriate for non-directories/regular files. */
#define WOFS_OTHER_FLMASK (FS_NODUMP_FL | FS_NOATIME_FL)

#define S_IFPSEUDO		 	0xFFFF
#define S_ISPSEUDO(mode) 	(mode == S_IFPSEUDO)
/*
 * Debug code
 */
#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

/* #define wofs_dbg(s, args...)		pr_debug(s, ## args) */
#define wofs_dbg(s, args ...)		    pr_info("cpu-%d: "s, smp_processor_id(), ## args)
#define wofs_dbg1(s, args ...)
#define wofs_err(sb, s, args ...)	    wofs_error_mng(sb, s, ## args)
#define wofs_warn(s, args ...)		pr_warn(s, ## args)
#define wofs_info(s, args ...)		pr_info("cpu-%d: "s, smp_processor_id(), ## args)

extern unsigned int wofs_dbgmask;
#define WOFS_DBGMASK_MMAPHUGE	        (0x00000001)
#define WOFS_DBGMASK_MMAP4K	        (0x00000002)
#define WOFS_DBGMASK_MMAPVERBOSE      (0x00000004)
#define WOFS_DBGMASK_MMAPVVERBOSE     (0x00000008)
#define WOFS_DBGMASK_VERBOSE	        (0x00000010)
#define WOFS_DBGMASK_TRANSACTION      (0x00000020)

#define wofs_dbg_mmap4k(s, args ...)		 \
	((wofs_dbgmask & WOFS_DBGMASK_MMAP4K) ? wofs_dbg(s, args) : 0)
#define wofs_dbg_mmapv(s, args ...)		 \
	((wofs_dbgmask & WOFS_DBGMASK_MMAPVERBOSE) ? wofs_dbg(s, args) : 0)
#define wofs_dbg_mmapvv(s, args ...)		 \
	((wofs_dbgmask & WOFS_DBGMASK_MMAPVVERBOSE) ? wofs_dbg(s, args) : 0)
#define wofs_dbg_verbose(s, args ...)		 \
	((wofs_dbgmask & WOFS_DBGMASK_VERBOSE) ? wofs_dbg(s, ##args) : 0)
#define wofs_dbgv(s, args ...)	         wofs_dbg_verbose(s, ##args)
#define wofs_dbg_trans(s, args ...)		 \
	((wofs_dbgmask & WOFS_DBGMASK_TRANSACTION) ? wofs_dbg(s, ##args) : 0)

#define WOFS_ASSERT(x) do {\
			       if (!(x))\
				       wofs_warn("assertion failed %s:%d: %s\n", \
			       __FILE__, __LINE__, #x);\
		       } while (0)

// #define wofs_set_bit		           __test_and_set_bit_le
// #define wofs_clear_bit		       __test_and_clear_bit_le
// #define wofs_find_next_zero_bit	   find_next_zero_bit_le

#define clear_opt(o, opt)	       (o &= ~WOFS_MOUNT_ ## opt)
#define set_opt(o, opt)		       (o |= WOFS_MOUNT_ ## opt)
#define test_opt(sb, opt)	       (WOFS_SB(sb)->s_mount_opt & WOFS_MOUNT_ ## opt)


#define	READDIR_END				   (ULONG_MAX)
#define	ANY_CPU					   (65536)

/* ======================= ANCHOR: Global values ========================= */
extern int measure_timing;
extern int wprotect;

/* ======================= ANCHOR: global struct ========================= */
/* A node in the linked list representing a range of pages */
struct wofs_range_node {
	struct list_head node;
	/* Block, inode */
	struct {
		unsigned long low;
		unsigned long high;
	};
};

/* ======================= ANCHOR: WOFS Includes ========================= */
#include "chash.h"
#include "rng_lock.h"
#include "stats.h"
#include "config.h"
#include "dw.h"
#include "bbuild.h"
#include "tlalloc.h"
#include "namei.h"
#include "linix.h"
#include "objm.h"
#include "super.h"
#include "inode.h"
#include "config.h"
#include "balloc.h"
#include "mprotect.h"
#include "generic_cachep.h"
#include "formater.h"

static inline void prefetcht0(const void *x) {
	asm volatile("prefetcht0 %0" : : "m" (*(const char* )x));
}

static inline void prefetcht2(const void *x) {
	asm volatile("prefetcht2 %0" : : "m" (*(const char* )x));
}

/* blk_addr is the offset addr in NVMM */
static inline void *wofs_get_block(struct super_block *sb, u64 blk_addr)
{
	struct wofs_super_block *ps = wofs_get_super(sb, WOFS_FIRST_SUPER_BLK);

	return blk_addr ? ((void *)ps + blk_addr) : NULL;
}

/* get in nvmm reference */
static inline int wofs_get_reference(struct super_block *sb, u64 block,
	void *dram, void **nvmm, size_t size)
{
	int rc;

	*nvmm = wofs_get_block(sb, block);
	rc = memcpy_mcsafe(dram, *nvmm, size);
	return rc;
}

static inline u64 wofs_get_addr_off(struct wofs_sb_info *sbi, void *addr)
{
	WOFS_ASSERT((addr >= sbi->virt_addr) &&
			  (addr < (sbi->virt_addr + sbi->initsize)));
	return (u64)(addr - sbi->virt_addr);
}

static inline u64 wofs_get_dblk_by_addr(struct wofs_sb_info *sbi, void *d_addr)
{
	struct super_block *sb = sbi->sb;
	WOFS_ASSERT(d_addr >= sbi->d_addr && 
			  d_addr < (sbi->d_addr + sbi->d_size));
	return (u64)(d_addr - sbi->d_addr) / WOFS_PBLK_SZ(sbi);
}

static inline u64 wofs_get_addr_by_dblk(struct wofs_sb_info *sbi, u64 d_blk)
{
	struct super_block *sb = sbi->sb;
	return (u64)(sbi->d_addr + (d_blk * WOFS_PBLK_SZ(sbi)));
}

/* Mask out flags that are inappropriate for the given type of inode. */
static inline __le32 wofs_mask_flags(umode_t mode, __le32 flags)
{
	flags &= cpu_to_le32(WOFS_FL_INHERITED);
	if (S_ISDIR(mode))
		return flags;
	else if (S_ISREG(mode))
		return flags & cpu_to_le32(WOFS_REG_FLMASK);
	else
		return flags & cpu_to_le32(WOFS_OTHER_FLMASK);
}

/* ======================= ANCHOR: pmem specific function ========================= */
static inline int memcpy_to_pmem_nocache(void *dst, const void *src,
	unsigned int size)
{
	int ret;

	ret = __copy_from_user_inatomic_nocache(dst, src, size);

	return ret;
}

extern long __copy_user_nocache_nofence(void *dst, const void __user *src,
				unsigned size, int zerorest);

static inline int memcpy_to_pmem_nocache_nofence(void *dst, const void *src,
	unsigned int size)
{
	int ret;

	ret = __copy_user_nocache_nofence(dst, src, size, 0);

	return ret;
}

static inline int memcpy_to_pmem_avx_nocache(char *start_addr, __user const void *usrc,
	unsigned int size)
{
	int ret;
	
	// check 64-byte alignment
	if (((unsigned long)start_addr & 0x3f) == 0)
	{
		// allocate src_addr aligned to 64 bytes
		char *src_addr = (char *)kmalloc(size + 64, GFP_KERNEL);
		if (!src_addr)
			return -ENOMEM;
		// align src_addr to 64 bytes
		src_addr = (char *)(((unsigned long)src_addr + 63) & ~0x3f);

		size_t i;

		copy_from_user(src_addr, usrc, size);
		
		kernel_fpu_begin();
		// 每次处理 256 字节
		for (i = 0; i + 256 <= size; i += 256)
		{
			asm volatile (
				"vmovdqa64 (%[src]), %%zmm0 \n"   // 从 src_addr 加载 64 字节到 zmm0
				"vmovdqa64 64(%[src]), %%zmm1 \n" // 从 src_addr + 64 加载 64 字节到 zmm1
				"vmovdqa64 128(%[src]), %%zmm2 \n" // 从 src_addr + 128 加载 64 字节到 zmm2
				"vmovdqa64 192(%[src]), %%zmm3 \n" // 从 src_addr + 192 加载 64 字节到 zmm3

				"vmovntdq %%zmm0, (%[dst]) \n"   // 将 zmm0 中的数据非临时存储到 start_addr
				"vmovntdq %%zmm1, 64(%[dst]) \n" // 将 zmm1 中的数据非临时存储到 start_addr + 64
				"vmovntdq %%zmm2, 128(%[dst]) \n" // 将 zmm2 中的数据非临时存储到 start_addr + 128
				"vmovntdq %%zmm3, 192(%[dst]) \n" // 将 zmm3 中的数据非临时存储到 start_addr + 192
				:
				: [src] "r" (src_addr + i), [dst] "r" (start_addr + i)
				: "zmm0", "zmm1", "zmm2", "zmm3", "memory"
			);
		}
		kernel_fpu_end();

		// 处理剩余的数据
		for (; i < size; ++i)
		{
			start_addr[i] = src_addr[i];
		}
		PERSISTENT_BARRIER();

		kfree(src_addr);
	} else {
		ret = __copy_from_user_inatomic_nocache(start_addr, usrc, size);
	}

	return ret;
}

/* assumes the length to be 4-byte aligned */
static inline void memset_nt(void *dest, uint32_t dword, size_t length)
{
	uint64_t dummy1, dummy2;
	uint64_t qword = ((uint64_t)dword << 32) | dword;
	
	BUG_ON(length > ((u64)1 << 32));
	
	asm volatile ("movl %%edx,%%ecx\n"
		"andl $63,%%edx\n"
		"shrl $6,%%ecx\n"
		"jz 9f\n"
		"1:	 movnti %%rax,(%%rdi)\n"
		"2:	 movnti %%rax,1*8(%%rdi)\n"
		"3:	 movnti %%rax,2*8(%%rdi)\n"
		"4:	 movnti %%rax,3*8(%%rdi)\n"
		"5:	 movnti %%rax,4*8(%%rdi)\n"
		"8:	 movnti %%rax,5*8(%%rdi)\n"
		"7:	 movnti %%rax,6*8(%%rdi)\n"
		"8:	 movnti %%rax,7*8(%%rdi)\n"
		"leaq 64(%%rdi),%%rdi\n"
		"decl %%ecx\n"
		"jnz 1b\n"
		"9:	movl %%edx,%%ecx\n"
		"andl $7,%%edx\n"
		"shrl $3,%%ecx\n"
		"jz 11f\n"
		"10:	 movnti %%rax,(%%rdi)\n"
		"leaq 8(%%rdi),%%rdi\n"
		"decl %%ecx\n"
		"jnz 10b\n"
		"11:	 movl %%edx,%%ecx\n"
		"shrl $2,%%ecx\n"
		"jz 12f\n"
		"movnti %%eax,(%%rdi)\n"
		"12:\n"
		: "=D"(dummy1), "=d" (dummy2)
		: "D" (dest), "a" (qword), "d" (length)
		: "memory", "rcx");
}

static inline void memset_nt_large(void *dest, uint32_t dword, size_t length)
{
	uint64_t qword = ((uint64_t)dword << 32) | dword;
	BUG_ON(length % 4 != 0);
	for (; length >= 64; length -= 64, dest = (char *)dest + 64) {
		memcpy_flushcache((uint64_t *)dest, &qword, sizeof(uint64_t));
		memcpy_flushcache((uint64_t *)dest + 1, &qword, sizeof(uint64_t));
		memcpy_flushcache((uint64_t *)dest + 2, &qword, sizeof(uint64_t));
		memcpy_flushcache((uint64_t *)dest + 3, &qword, sizeof(uint64_t));
		memcpy_flushcache((uint64_t *)dest + 4, &qword, sizeof(uint64_t));
		memcpy_flushcache((uint64_t *)dest + 5, &qword, sizeof(uint64_t));
		memcpy_flushcache((uint64_t *)dest + 6, &qword, sizeof(uint64_t));
		memcpy_flushcache((uint64_t *)dest + 7, &qword, sizeof(uint64_t));
	}
	for (; length >= 8; length -= 8, dest = (char *)dest + 8)
		memcpy_flushcache((uint64_t *)dest, &qword, sizeof(uint64_t));
	if (length == 4)
		memcpy_flushcache((uint32_t *)dest, &dword, sizeof(uint32_t));
}

static inline u64 _round_down(u64 value, u64 align)
{
	BUG_ON(!align);
	if (align & (align - 1) == 0) {
		return round_down(value, align);
	}
	else {
		return (value / align) * align;
	}
}

static inline u64 _round_up(u64 value, u64 align)
{
	BUG_ON(!align);
	/* check if align is power of 2 */
	if (align && (!(align & (align - 1)))) {
		return round_up(value, align);
	}
	else {
		return (value / align + 1) * align;
	}
}
/* ======================= ANCHOR: mlist.c ========================= */
void wofs_range_trv(struct list_head *head);
int wofs_range_insert_range(struct super_block *sb, struct list_head *head, 
                          unsigned long range_low, unsigned long range_high);
int wofs_range_insert_value(struct super_block *sb, struct list_head *head, unsigned long value);
bool wofs_range_find_value(struct super_block *sb, struct list_head *head, unsigned long value);
unsigned long wofs_range_pop(struct list_head *head, u64 *len);
int wofs_range_remove(struct super_block *sb, struct list_head *head, unsigned long value);
int wofs_range_remove_range(struct super_block *sb, struct list_head *head, 
                          unsigned long range_low, unsigned long range_high);
void wofs_range_free_all(struct list_head *head);

/* ======================= ANCHOR: tlalloc.c ========================= */
void tl_build_free_param(tlfree_param_t *param, u64 blk, u64 num, u16 flags);
void tl_build_alloc_param(tlalloc_param_t *param, u64 req, u16 flags);
void tl_build_restore_param(tlrestore_param_t *param, u64 blk, u64 num, u16 flags);
int tl_alloc_init(tl_allocator_t *alloc, int cpuid, u64 blk, u64 num, u32 blk_size, u32 meta_size);
s32 tlalloc(tl_allocator_t *alloc, tlalloc_param_t *param);
void tlfree(tl_allocator_t *alloc, tlfree_param_t *param);
void tlrestore(tl_allocator_t *alloc, tlrestore_param_t *param);
void tl_destory(tl_allocator_t *alloc);

/* ======================= ANCHOR: rebuild.c ========================= */
void wofs_init_header(struct super_block *sb, struct wofs_inode_info_header *sih, 
                    u16 i_mode);

/* ======================= ANCHOR: bbuild.c ========================= */
unsigned long wofs_get_bm_size(struct super_block *sb);
void wofs_set_bm(struct wofs_sb_info *sbi, u16 bmblk, u64 blk);
void wofs_clear_bm(struct wofs_sb_info *sbi, u16 bmblk, u64 blk);
int wofs_recovery(struct super_block *sb);
int wofs_save_layouts(struct super_block *sb);
int wofs_save_regions(struct super_block *sb);

/* ======================= ANCHOR: balloc.c ========================= */
u64 get_version(struct wofs_sb_info *sbi);
int wofs_layouts_init(struct wofs_sb_info *sbi, int cpus);
int wofs_layouts_free(struct wofs_sb_info *sbi);
unsigned long wofs_count_free_blocks(struct super_block *sb);
int wofs_alloc_blocks(struct super_block *sb, unsigned long *blks, bool zero, struct wofs_layout_prep *prep);

/* ======================= ANCHOR: file.c ========================= */
extern const struct inode_operations wofs_file_inode_operations;
extern const struct file_operations wofs_dax_file_operations;

/* ======================= ANCHOR: dir.c ========================= */
extern const struct file_operations wofs_dir_operations;

/* ======================= ANCHOR: symlink.c ========================= */
extern const struct inode_operations wofs_symlink_inode_operations;
int wofs_block_symlink(struct super_block *sb, struct inode *inode, 
					 const char *symname, int len, void *out_blk_addr);

/* ======================= ANCHOR: ioctl.c ========================= */
long wofs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
long wofs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

/* ======================= ANCHOR: inode.c ========================= */
extern const struct address_space_operations wofs_aops_dax;
void wofs_init_inode(struct inode *inode, struct wofs_inode *pi);
int wofs_init_free_inode_list(struct super_block *sb, bool is_init);
int wofs_init_free_inode_list_percore(struct super_block *sb, int cpuid, bool is_init);
int inode_mgr_init(struct wofs_sb_info *sbi, inode_mgr_t *mgr);
int inode_mgr_alloc(inode_mgr_t *mgr, u32 *ret_ino);
int inode_mgr_free(inode_mgr_t *mgr, u32 ino);
int inode_mgr_destroy(inode_mgr_t *mgr);
int inode_mgr_restore(inode_mgr_t *mgr, u32 ino);
struct inode *wofs_iget_opened(struct super_block *sb, unsigned long ino);
struct inode *wofs_iget(struct super_block *sb, unsigned long ino);
void *wofs_inode_get_slot(struct wofs_inode_info_header *sih, u64 offset);
struct inode *wofs_create_inode(enum wofs_new_inode_type type, struct inode *dir, 
							  u64 ino, umode_t mode, size_t size, dev_t rdev, 
							  const struct qstr *qstr);
int wofs_getattr(const struct path *path, struct kstat *stat,
		 	   u32 request_mask, unsigned int query_flags);
int wofs_notify_change(struct dentry *dentry, struct iattr *attr);
int wofs_write_inode(struct inode *inode, struct writeback_control *wbc);
void wofs_evict_inode(struct inode *inode);
int __wofs_free_inode_blks(struct super_block *sb, struct wofs_inode *pi,
					   		   		   struct wofs_inode_info_header *sih);
int wofs_free_inode_blks(struct super_block *sb, struct wofs_inode *pi,
					   struct wofs_inode_info_header *sih);

/* ======================= ANCHOR: namei.c ========================= */
extern const struct inode_operations wofs_dir_inode_operations;
extern const struct inode_operations wofs_special_inode_operations;
struct wofs_dentry *wofs_dentry_by_ix_from_blk(u64 blk_addr, u16 ix);
struct dentry *wofs_get_parent(struct dentry *child);
int wofs_insert_dir_table(struct super_block *sb, struct wofs_inode_info_header *sih, const char *name, 
				  	    int namelen, void *direntry);
int wofs_remove_dir_table(struct super_block *sb, struct wofs_inode_info_header *sih, 
						 const char *name, int namelen, void **ret_entry);
void wofs_destory_dir_table(struct super_block *sb, struct wofs_inode_info_header *sih);

/* ======================= ANCHOR: meta.c ========================= */
int wofs_format_meta(struct super_block *sb);

/* ======================= ANCHOR: objm.c ========================= */
obj_ref_inode_t *ref_inode_create(u64 addr, u32 ino);
void ref_inode_destroy(obj_ref_inode_t *ref);
obj_ref_attr_t *ref_attr_create(u64 addr, u32 ino, u16 from_pkg, u64 dep_ofs);
void ref_attr_destroy(obj_ref_attr_t *ref);
obj_ref_dentry_t *ref_dentry_create(u64 addr, const char *name, u32 len, u32 ino, u32 parent_ino);
void ref_dentry_destroy(obj_ref_dentry_t *ref);
obj_ref_data_t *ref_data_create(u64 addr, u32 ino, u64 ofs, u32 num, u64 data_offset);
void ref_data_destroy(obj_ref_data_t *ref);
int obj_mgr_init(struct wofs_sb_info *sbi, u32 cpus, obj_mgr_t *mgr);
void obj_mgr_destroy(obj_mgr_t *mgr);
int obj_mgr_load_dobj_control(obj_mgr_t *mgr, void *obj_ref, u8 type);
int obj_mgr_unload_dobj_control(obj_mgr_t *mgr, void *obj_ref, u8 type);
int obj_mgr_get_dobjs(obj_mgr_t *mgr, int cpuid, u32 ino, u8 type, void **obj_refs);
int obj_mgr_load_imap_control(obj_mgr_t *mgr, struct wofs_inode_info_header *sih);
int obj_mgr_unload_imap_control(obj_mgr_t *mgr, struct wofs_inode_info_header *sih);
struct wofs_inode_info_header *obj_mgr_get_imap_inode(obj_mgr_t *mgr, u32 ino);
int reclaim_dram_data(obj_mgr_t *mgr, struct wofs_inode_info_header *sih, data_update_t *update);
int reclaim_dram_attr(obj_mgr_t *mgr, struct wofs_inode_info_header *sih);
int reclaim_dram_create(obj_mgr_t *mgr, struct wofs_inode_info_header *sih, obj_ref_dentry_t *ref);
int reclaim_dram_unlink(obj_mgr_t *mgr, struct wofs_inode_info_header *sih);
int ur_dram_data(obj_mgr_t *mgr, struct wofs_inode_info_header *sih, data_update_t *update);
int ur_dram_latest_attr(obj_mgr_t *mgr, struct wofs_inode_info_header *sih, attr_update_t *update);
int ur_dram_latest_inode(obj_mgr_t *mgr, struct wofs_inode_info_header *sih, inode_update_t *update);
int check_pkg_valid(void *obj_start, u32 len, struct wofs_obj_hdr *last_obj_hdr);
int create_new_inode_pkg(struct wofs_sb_info *sbi, u16 mode, const char *name,
                         struct wofs_inode_info_header *sih, struct wofs_inode_info_header *psih,
                         in_pkg_param_t *in_param, out_pkg_param_t *out_param);
int create_unlink_pkg(struct wofs_sb_info *sbi, struct wofs_inode_info_header *sih,
                      struct wofs_inode_info_header *psih, obj_ref_dentry_t *ref,
                      in_pkg_param_t *in_param, out_pkg_param_t *out_param);
int update_data_pkg(struct wofs_sb_info *sbi, struct wofs_inode_info_header *sih,
                    u64 hdr_addr, u64 num_kv_pairs, ...);
int create_data_pkg(struct wofs_sb_info *sbi, struct wofs_inode_info_header *sih,
                    u64 data_addr, off_t offset, size_t size, u64 num,
                    in_pkg_param_t *in_param, out_pkg_param_t *out_param);
int create_attr_pkg(struct wofs_sb_info *sbi, struct wofs_inode_info_header *sih,
                    int link_change, int size_change,
                    in_pkg_param_t *in_param, out_pkg_param_t *out_param);
int create_rename_pkg(struct wofs_sb_info *sbi, const char *new_name,
                      obj_ref_dentry_t *ref, struct wofs_inode_info_header *sih,
                      struct wofs_inode_info_header *psih, struct wofs_inode_info_header *npsih,
                      out_pkg_param_t *unlink_out_param, out_pkg_param_t *create_out_param);
int create_symlink_pkg(struct wofs_sb_info *sbi, u16 mode, const char *name, const char *symname, u32 ino,
                       u64 symaddr, struct wofs_inode_info_header *sih, struct wofs_inode_info_header *psih,
                       out_pkg_param_t *data_out_param, out_pkg_param_t *create_out_param);

/* ======================= ANCHOR: rebuild.c ========================= */
int wofs_rebuild_inode(struct super_block *sb, struct wofs_inode_info *si, u32 ino, bool build_blks);

/* ======================= ANCHOR: linix.c ========================= */
int linix_init(struct linix *ix, u64 num_slots);
int linix_destroy(struct linix *ix);
int linix_extend(struct linix *ix);
u64 linix_get(struct linix *ix, u64 index);
int linix_insert(struct linix *ix, u64 index, u64 blk_addr, bool extend);
int linix_delete(struct linix *ix, u64 index, u64 last_index, bool shrink);

/* ======================= ANCHOR: gc.c ========================= */
#if 0
int wofs_friendly_gc(struct super_block *sb);
int wofs_start_equalizer(struct super_block *sb);
int wofs_terminal_equalizer(struct super_block *sb);
#endif

/* ======================= ANCHOR: stats.c ========================= */
void wofs_get_timing_stats(void);
void wofs_get_IO_stats(void);
void wofs_clear_stats(struct super_block *sb);

/* ======================= ANCHOR: sysfs.c ========================= */
extern const char *proc_dirname;
extern struct proc_dir_entry *wofs_proc_root;
void wofs_sysfs_init(struct super_block *sb);
void wofs_sysfs_exit(struct super_block *sb);


/* ======================= ANCHOR: Static Utils ========================= */
static inline int wofs_get_cpuid(struct super_block *sb)
{
	struct wofs_sb_info *sbi = WOFS_SB(sb);

	return smp_processor_id() % sbi->cpus;
}

#define BITS32_TO_BITS64(hi, lo) (((u64)(hi) << 32) | (lo))

static u64 inline get_pm_blk_addr(struct wofs_sb_info *sbi, u32 blk)
{
    return (u64)sbi->virt_addr + ((u64)blk << WOFS_BLK_SHIFT);
}

static u64 inline get_pm_entry_addr(struct wofs_sb_info *sbi, u32 blk, u32 entrynr)
{
    return get_pm_blk_addr(sbi, blk) + ((u64)entrynr << WOFS_MTA_SHIFT);
}

static u64 inline get_pm_addr(struct wofs_sb_info *sbi, u64 offset)
{
    return (u64)sbi->virt_addr + offset;
}

static u64 inline get_pm_addr_by_data_ref(struct wofs_sb_info *sbi, obj_ref_data_t *ref, u64 in_file_offset)
{
	BUG_ON(!ref);
	if (in_file_offset < ref->ofs) {
		return 0;
	}
	return get_pm_addr(sbi, ref->data_offset) + in_file_offset - ref->ofs;
}

static u64 inline get_pm_offset(struct wofs_sb_info *sbi, u64 addr)
{
    return addr - (u64)sbi->virt_addr;
}

static u64 inline get_pm_blk_offset(struct wofs_sb_info *sbi, u64 blk)
{
    return (blk << WOFS_BLK_SHIFT);
}

static u64 inline get_pm_blk(struct wofs_sb_info *sbi, u64 addr)
{
    return (u64)(get_pm_offset(sbi, addr) >> WOFS_BLK_SHIFT);
}

static u64 inline get_layout_idx(struct wofs_sb_info *sbi, u64 offset)
{
	u64 idx = (offset - get_pm_offset(sbi, sbi->pack_layout.fs_start)) / (sbi->per_layout_blks << WOFS_BLK_SHIFT);
    return idx >= sbi->num_layout ? sbi->num_layout - 1 : idx;
}

static inline struct tl_allocator *get_tl_allocator(struct wofs_sb_info *sbi, u64 offset)
{
    u64 idx = get_layout_idx(sbi, offset);
    return &sbi->layouts[idx].allocator;
} 

// BKDR String Hash Function
static inline unsigned long BKDRHash(const char *str, int length)
{
	unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
	unsigned long hash = 0;
	int i;

	for (i = 0; i < length; i++)
		hash = hash * seed + (*str++);

	return hash;
}

#define use_droot(droot, type) (spin_lock(&droot->type##_lock))
#define rls_droot(droot, type) (spin_unlock(&droot->type##_lock))

#define use_pending_list(pending_list) (spin_lock(pending_list->lock))
#define rls_pending_list(pending_list) (spin_unlock(pending_list->lock))

static inline void wofs_sync_super(struct super_block *sb)
{
	struct wofs_sb_info 	  *sbi = WOFS_SB(sb);
	struct wofs_super_block *super = wofs_get_super(sb, WOFS_FIRST_SUPER_BLK);
	struct wofs_super_block *super_redund = wofs_get_super(sb, WOFS_SECOND_SUPER_BLK);
	unsigned long 		  irq_flags = 0;

	wofs_memunlock_super(sb, WOFS_FIRST_SUPER_BLK, &irq_flags);
	memcpy_to_pmem_nocache((void *)super, (void *)sbi->wofs_sb,
							WOFS_SB_SIZE(sbi));
	wofs_memlock_super(sb, WOFS_SECOND_SUPER_BLK, &irq_flags);
	PERSISTENT_BARRIER();
	
	wofs_memunlock_super(sb, WOFS_SECOND_SUPER_BLK, &irq_flags);
	memcpy_to_pmem_nocache((void *)super_redund, (void *)sbi->wofs_sb,
							WOFS_SB_SIZE(sbi));
	wofs_memlock_super(sb, WOFS_SECOND_SUPER_BLK, &irq_flags);
	PERSISTENT_BARRIER();
}

/* Update checksum for the DRAM copy */
static inline void wofs_update_super_crc(struct super_block *sb)
{
	struct wofs_sb_info *sbi = WOFS_SB(sb);
	u32 			  crc = 0;

	sbi->wofs_sb->s_wtime = cpu_to_le32(get_seconds());
	sbi->wofs_sb->s_sum = 0;
	crc = wofs_crc32c(~0, (__u8 *)sbi->wofs_sb + sizeof(__le32),
			sizeof(struct wofs_super_block) - sizeof(__le32) + sbi->wofs_sb->s_private_data_len);
	sbi->wofs_sb->s_sum = cpu_to_le32(crc);
}

static inline void ssleep_interruptible(unsigned int seconds)
{
	if (seconds > 0) {
		msleep_interruptible(seconds * 1000);
	}
}

#endif /* _WOFS_H */