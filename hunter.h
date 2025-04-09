#ifndef _HK_H
#define _HK_H

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

#define TRANS_ADDR_TO_OFS(sbi, addr)  (addr == 0 ? 0 : ((u64)(addr) - (u64)(sbi)->virt_addr))   
#define TRANS_OFS_TO_ADDR(sbi, ofs)   (ofs == 0 ? 0 : ((u64)(ofs) + (sbi)->virt_addr))
#define GET_ALIGNED_BLKNR(ofs_addr) ((ofs_addr) >> HUNTER_BLK_SHIFT)

#define HK_VALID_UMOUNT     0xffffffff
#define HK_INVALID_UMOUNT   0x00000000

#define ENABLE_META_ASYNC(sb)	test_opt(sb, META_ASYNC)
#define ENABLE_META_LOCAL(sb)	test_opt(sb, META_LOCAL)
#define ENABLE_META_LFS(sb)		test_opt(sb, META_LFS)
#define ENABLE_META_PACK(sb)	test_opt(sb, META_PACK)
#define ENABLE_HISTORY_W(sb)	test_opt(sb, HISTORY_W)

/*
 * hunter inode flags
 *
 * HK_EOFBLOCKS_FL			 There are blocks allocated beyond eof
 */
#define HK_EOFBLOCKS_FL      0x20000000

/* Flags that should be inherited by new inodes from their parent. */
#define HK_FL_INHERITED (FS_SECRM_FL | FS_UNRM_FL | FS_COMPR_FL | \
						FS_SYNC_FL | FS_NODUMP_FL | FS_NOATIME_FL |	\
						FS_COMPRBLK_FL | FS_NOCOMP_FL | \
						FS_JOURNAL_DATA_FL | FS_NOTAIL_FL | FS_DIRSYNC_FL)
/* Flags that are appropriate for regular files (all but dir-specific ones). */
#define HK_REG_FLMASK 	(~(FS_DIRSYNC_FL | FS_TOPDIR_FL))
/* Flags that are appropriate for non-directories/regular files. */
#define HK_OTHER_FLMASK (FS_NODUMP_FL | FS_NOATIME_FL)

#define S_IFPSEUDO		 	0xFFFF
#define S_ISPSEUDO(mode) 	(mode == S_IFPSEUDO)
/*
 * Debug code
 */
#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

/* #define hk_dbg(s, args...)		pr_debug(s, ## args) */
#define hk_dbg(s, args ...)		    pr_info("cpu-%d: "s, smp_processor_id(), ## args)
#define hk_dbg1(s, args ...)
#define hk_err(sb, s, args ...)	    hk_error_mng(sb, s, ## args)
#define hk_warn(s, args ...)		pr_warn(s, ## args)
#define hk_info(s, args ...)		pr_info("cpu-%d: "s, smp_processor_id(), ## args)

extern unsigned int hk_dbgmask;
#define HK_DBGMASK_MMAPHUGE	        (0x00000001)
#define HK_DBGMASK_MMAP4K	        (0x00000002)
#define HK_DBGMASK_MMAPVERBOSE      (0x00000004)
#define HK_DBGMASK_MMAPVVERBOSE     (0x00000008)
#define HK_DBGMASK_VERBOSE	        (0x00000010)
#define HK_DBGMASK_TRANSACTION      (0x00000020)

#define hk_dbg_mmap4k(s, args ...)		 \
	((hk_dbgmask & HK_DBGMASK_MMAP4K) ? hk_dbg(s, args) : 0)
#define hk_dbg_mmapv(s, args ...)		 \
	((hk_dbgmask & HK_DBGMASK_MMAPVERBOSE) ? hk_dbg(s, args) : 0)
#define hk_dbg_mmapvv(s, args ...)		 \
	((hk_dbgmask & HK_DBGMASK_MMAPVVERBOSE) ? hk_dbg(s, args) : 0)
#define hk_dbg_verbose(s, args ...)		 \
	((hk_dbgmask & HK_DBGMASK_VERBOSE) ? hk_dbg(s, ##args) : 0)
#define hk_dbgv(s, args ...)	         hk_dbg_verbose(s, ##args)
#define hk_dbg_trans(s, args ...)		 \
	((hk_dbgmask & HK_DBGMASK_TRANSACTION) ? hk_dbg(s, ##args) : 0)

#define HK_ASSERT(x) do {\
			       if (!(x))\
				       hk_warn("assertion failed %s:%d: %s\n", \
			       __FILE__, __LINE__, #x);\
		       } while (0)

// #define hk_set_bit		           __test_and_set_bit_le
// #define hk_clear_bit		       __test_and_clear_bit_le
// #define hk_find_next_zero_bit	   find_next_zero_bit_le

#define clear_opt(o, opt)	       (o &= ~HUNTER_MOUNT_ ## opt)
#define set_opt(o, opt)		       (o |= HUNTER_MOUNT_ ## opt)
#define test_opt(sb, opt)	       (HK_SB(sb)->s_mount_opt & HUNTER_MOUNT_ ## opt)


#define	READDIR_END				   (ULONG_MAX)
#define	ANY_CPU					   (65536)

/* ======================= ANCHOR: Global values ========================= */
extern int measure_timing;
extern int wprotect;

/* ======================= ANCHOR: global struct ========================= */
/* A node in the linked list representing a range of pages */
struct hk_range_node {
	struct list_head node;
	/* Block, inode */
	struct {
		unsigned long low;
		unsigned long high;
	};
};

/* ======================= ANCHOR: HUNTER Includes ========================= */
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
#include "meta.h"
#include "mprotect.h"
#include "cmt.h"
#include "generic_cachep.h"
#include "dbg.h"
#include "formater.h"

static inline void prefetcht0(const void *x) {
	asm volatile("prefetcht0 %0" : : "m" (*(const char* )x));
}

static inline void prefetcht2(const void *x) {
	asm volatile("prefetcht2 %0" : : "m" (*(const char* )x));
}

/* blk_addr is the offset addr in NVMM */
static inline void *hk_get_block(struct super_block *sb, u64 blk_addr)
{
	struct hk_super_block *ps = hk_get_super(sb, HUNTER_FIRST_SUPER_BLK);

	return blk_addr ? ((void *)ps + blk_addr) : NULL;
}

/* get in nvmm reference */
static inline int hk_get_reference(struct super_block *sb, u64 block,
	void *dram, void **nvmm, size_t size)
{
	int rc;

	*nvmm = hk_get_block(sb, block);
	rc = memcpy_mcsafe(dram, *nvmm, size);
	return rc;
}

static inline u64 hk_get_addr_off(struct hk_sb_info *sbi, void *addr)
{
	HK_ASSERT((addr >= sbi->virt_addr) &&
			  (addr < (sbi->virt_addr + sbi->initsize)));
	return (u64)(addr - sbi->virt_addr);
}

static inline u64 hk_get_dblk_by_addr(struct hk_sb_info *sbi, void *d_addr)
{
	struct super_block *sb = sbi->sb;
	HK_ASSERT(d_addr >= sbi->d_addr && 
			  d_addr < (sbi->d_addr + sbi->d_size));
	return (u64)(d_addr - sbi->d_addr) / HK_PBLK_SZ(sbi);
}

static inline u64 hk_get_addr_by_dblk(struct hk_sb_info *sbi, u64 d_blk)
{
	struct super_block *sb = sbi->sb;
	return (u64)(sbi->d_addr + (d_blk * HK_PBLK_SZ(sbi)));
}

/* Mask out flags that are inappropriate for the given type of inode. */
static inline __le32 hk_mask_flags(umode_t mode, __le32 flags)
{
	flags &= cpu_to_le32(HK_FL_INHERITED);
	if (S_ISDIR(mode))
		return flags;
	else if (S_ISREG(mode))
		return flags & cpu_to_le32(HK_REG_FLMASK);
	else
		return flags & cpu_to_le32(HK_OTHER_FLMASK);
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
void hk_range_trv(struct list_head *head);
int hk_range_insert_range(struct super_block *sb, struct list_head *head, 
                          unsigned long range_low, unsigned long range_high);
int hk_range_insert_value(struct super_block *sb, struct list_head *head, unsigned long value);
bool hk_range_find_value(struct super_block *sb, struct list_head *head, unsigned long value);
unsigned long hk_range_pop(struct list_head *head, u64 *len);
int hk_range_remove(struct super_block *sb, struct list_head *head, unsigned long value);
int hk_range_remove_range(struct super_block *sb, struct list_head *head, 
                          unsigned long range_low, unsigned long range_high);
void hk_range_free_all(struct list_head *head);

/* ======================= ANCHOR: tlalloc.c ========================= */
void tl_build_free_param(tlfree_param_t *param, u64 blk, u64 num, u16 flags);
void tl_build_alloc_param(tlalloc_param_t *param, u64 req, u16 flags);
void tl_build_restore_param(tlrestore_param_t *param, u64 blk, u64 num, u16 flags);
int tl_alloc_init(tl_allocator_t *alloc, int cpuid, u64 blk, u64 num, u32 blk_size, u32 meta_size);
s32 tlalloc(tl_allocator_t *alloc, tlalloc_param_t *param);
void tlfree(tl_allocator_t *alloc, tlfree_param_t *param);
void tlrestore(tl_allocator_t *alloc, tlrestore_param_t *param);
void tl_destory(tl_allocator_t *alloc);
void tl_dump_allocator(tl_allocator_t *alloc);

/* ======================= ANCHOR: rebuild.c ========================= */
void hk_init_header(struct super_block *sb, struct hk_inode_info_header *sih, 
                    u16 i_mode);

/* ======================= ANCHOR: bbuild.c ========================= */
unsigned long hk_get_bm_size(struct super_block *sb);
void hk_set_bm(struct hk_sb_info *sbi, u16 bmblk, u64 blk);
void hk_clear_bm(struct hk_sb_info *sbi, u16 bmblk, u64 blk);
int hk_recovery(struct super_block *sb);
int hk_save_layouts(struct super_block *sb);
int hk_save_regions(struct super_block *sb);

/* ======================= ANCHOR: balloc.c ========================= */
u64 get_version(struct hk_sb_info *sbi);
int hk_layouts_init(struct hk_sb_info *sbi, int cpus);
int hk_layouts_free(struct hk_sb_info *sbi);
int hk_find_gaps(struct super_block *sb, int cpuid);
unsigned long hk_count_free_blocks(struct super_block *sb);
int hk_alloc_blocks(struct super_block *sb, unsigned long *blks, bool zero, struct hk_layout_prep *prep);
int hk_release_layout(struct super_block *sb, int cpuid, u64 blks, bool rls_all);

/* ======================= ANCHOR: file.c ========================= */
extern const struct inode_operations hk_file_inode_operations;
extern const struct file_operations hk_dax_file_operations;

/* ======================= ANCHOR: dir.c ========================= */
extern const struct file_operations hk_dir_operations;

/* ======================= ANCHOR: symlink.c ========================= */
extern const struct inode_operations hk_symlink_inode_operations;
int hk_block_symlink(struct super_block *sb, struct inode *inode, 
					 const char *symname, int len, void *out_blk_addr);

/* ======================= ANCHOR: ioctl.c ========================= */
long hk_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
long hk_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

/* ======================= ANCHOR: inode.c ========================= */
extern const struct address_space_operations hk_aops_dax;
void hk_init_inode(struct inode *inode, struct hk_inode *pi);
int hk_init_free_inode_list(struct super_block *sb, bool is_init);
int hk_init_free_inode_list_percore(struct super_block *sb, int cpuid, bool is_init);
int inode_mgr_init(struct hk_sb_info *sbi, inode_mgr_t *mgr);
int inode_mgr_alloc(inode_mgr_t *mgr, u32 *ret_ino);
int inode_mgr_free(inode_mgr_t *mgr, u32 ino);
int inode_mgr_destroy(inode_mgr_t *mgr);
int inode_mgr_restore(inode_mgr_t *mgr, u32 ino);
struct inode *hk_iget_opened(struct super_block *sb, unsigned long ino);
struct inode *hk_iget(struct super_block *sb, unsigned long ino);
void *hk_inode_get_slot(struct hk_inode_info_header *sih, u64 offset);
struct inode *hk_create_inode(enum hk_new_inode_type type, struct inode *dir, 
							  u64 ino, umode_t mode, size_t size, dev_t rdev, 
							  const struct qstr *qstr);
int hk_getattr(const struct path *path, struct kstat *stat,
		 	   u32 request_mask, unsigned int query_flags);
int hk_notify_change(struct dentry *dentry, struct iattr *attr);
int hk_write_inode(struct inode *inode, struct writeback_control *wbc);
void hk_evict_inode(struct inode *inode);
int __hk_free_inode_blks(struct super_block *sb, struct hk_inode *pi,
					   		   		   struct hk_inode_info_header *sih);
int hk_free_inode_blks(struct super_block *sb, struct hk_inode *pi,
					   struct hk_inode_info_header *sih);

/* ======================= ANCHOR: namei.c ========================= */
extern const struct inode_operations hk_dir_inode_operations;
extern const struct inode_operations hk_special_inode_operations;
struct hk_dentry *hk_dentry_by_ix_from_blk(u64 blk_addr, u16 ix);
int hk_append_dentry_innvm(struct super_block *sb, struct inode *dir, const char *name, 
						   int namelen, u64 ino, u16 link_change, struct hk_dentry **out_direntry);
struct dentry *hk_get_parent(struct dentry *child);
int hk_insert_dir_table(struct super_block *sb, struct hk_inode_info_header *sih, const char *name, 
				  	    int namelen, void *direntry);
int hk_remove_dir_table(struct super_block *sb, struct hk_inode_info_header *sih, 
						 const char *name, int namelen, void **ret_entry);
void hk_destory_dir_table(struct super_block *sb, struct hk_inode_info_header *sih);

/* ======================= ANCHOR: meta.c ========================= */
int hk_format_meta(struct super_block *sb);
int hk_stablisze_meta(struct super_block *sb);
bool hk_get_cur_commit(struct super_block *sb, struct hk_inode *pi, enum hk_entry_type type, 
					   struct hk_mentry *entry);
struct hk_mregion* hk_get_region_by_rgid(struct super_block *sb, int rgid);
int hk_applying_region(struct super_block *sb, struct hk_mregion *rg);
int hk_applying_region_to_inode(struct super_block *sb, struct hk_inode *pi);
int hk_commit_newattr(struct super_block *sb, u64 ino);
int hk_commit_newattr_indram(struct super_block *sb, struct inode *inode);
int hk_commit_newattr_innvm(struct super_block *sb, struct hk_inode *pi);
int hk_commit_linkchange(struct super_block *sb, u64 ino);
int hk_commit_linkchange_indram(struct super_block *sb, struct inode *inode);
int hk_commit_linkchange_innvm(struct super_block *sb, struct hk_inode *pi);
int hk_commit_sizechange(struct super_block *sb, struct inode *inode, loff_t ia_size);
int hk_commit_inode_state(struct super_block *sb, struct hk_inode_state *state);
u64 sm_get_addr_by_hdr(struct super_block *sb, u64 hdr);
struct hk_header *sm_get_hdr_by_addr(struct super_block *sb, u64 addr);
struct hk_layout_info *sm_get_layout_by_hdr(struct super_block *sb, u64 hdr);
int sm_remove_hdr(struct super_block *sb, struct hk_inode *pi, struct hk_header *hdr);
int sm_insert_hdr(struct super_block *sb, struct hk_inode *pi, struct hk_header *hdr);
int sm_invalid_hdr(struct super_block *sb, u64 blk_addr, u64 ino);
int sm_valid_hdr(struct super_block *sb, u64 blk_addr, u64 ino, u64 f_blk, u64 tstamp);
struct hk_journal* hk_get_journal_by_txid(struct super_block *sb, int txid);
struct hk_jentry* hk_get_jentry_by_slotid(struct super_block *sb, int txid, int slotid);
int hk_start_tx(struct super_block *sb, enum hk_journal_type jtype, ...);
int hk_finish_tx(struct super_block *sb, int txid);

/* ======================= ANCHOR: objm.c ========================= */
obj_ref_inode_t *ref_inode_create(u64 addr, u32 ino);
void ref_inode_destroy(obj_ref_inode_t *ref);
obj_ref_attr_t *ref_attr_create(u64 addr, u32 ino, u16 from_pkg, u64 dep_ofs);
void ref_attr_destroy(obj_ref_attr_t *ref);
obj_ref_dentry_t *ref_dentry_create(u64 addr, const char *name, u32 len, u32 ino, u32 parent_ino);
void ref_dentry_destroy(obj_ref_dentry_t *ref);
obj_ref_data_t *ref_data_create(u64 addr, u32 ino, u64 ofs, u32 num, u64 data_offset);
void ref_data_destroy(obj_ref_data_t *ref);
int obj_mgr_init(struct hk_sb_info *sbi, u32 cpus, obj_mgr_t *mgr);
void obj_mgr_destroy(obj_mgr_t *mgr);
int obj_mgr_load_dobj_control(obj_mgr_t *mgr, void *obj_ref, u8 type);
int obj_mgr_unload_dobj_control(obj_mgr_t *mgr, void *obj_ref, u8 type);
int obj_mgr_get_dobjs(obj_mgr_t *mgr, int cpuid, u32 ino, u8 type, void **obj_refs);
int obj_mgr_load_imap_control(obj_mgr_t *mgr, struct hk_inode_info_header *sih);
int obj_mgr_unload_imap_control(obj_mgr_t *mgr, struct hk_inode_info_header *sih);
struct hk_inode_info_header *obj_mgr_get_imap_inode(obj_mgr_t *mgr, u32 ino);
int reclaim_dram_data(obj_mgr_t *mgr, struct hk_inode_info_header *sih, data_update_t *update);
int reclaim_dram_attr(obj_mgr_t *mgr, struct hk_inode_info_header *sih);
int reclaim_dram_create(obj_mgr_t *mgr, struct hk_inode_info_header *sih, obj_ref_dentry_t *ref);
int reclaim_dram_unlink(obj_mgr_t *mgr, struct hk_inode_info_header *sih);
int ur_dram_data(obj_mgr_t *mgr, struct hk_inode_info_header *sih, data_update_t *update);
int ur_dram_latest_attr(obj_mgr_t *mgr, struct hk_inode_info_header *sih, attr_update_t *update);
int ur_dram_latest_inode(obj_mgr_t *mgr, struct hk_inode_info_header *sih, inode_update_t *update);
int check_pkg_valid(void *obj_start, u32 len, struct hk_obj_hdr *last_obj_hdr);
int create_new_inode_pkg(struct hk_sb_info *sbi, u16 mode, const char *name,
                         struct hk_inode_info_header *sih, struct hk_inode_info_header *psih,
                         in_pkg_param_t *in_param, out_pkg_param_t *out_param);
int create_unlink_pkg(struct hk_sb_info *sbi, struct hk_inode_info_header *sih,
                      struct hk_inode_info_header *psih, obj_ref_dentry_t *ref,
                      in_pkg_param_t *in_param, out_pkg_param_t *out_param);
int update_data_pkg(struct hk_sb_info *sbi, struct hk_inode_info_header *sih,
                    u64 hdr_addr, u64 num_kv_pairs, ...);
int create_data_pkg(struct hk_sb_info *sbi, struct hk_inode_info_header *sih,
                    u64 data_addr, off_t offset, size_t size, u64 num,
                    in_pkg_param_t *in_param, out_pkg_param_t *out_param);
int create_attr_pkg(struct hk_sb_info *sbi, struct hk_inode_info_header *sih,
                    int link_change, int size_change,
                    in_pkg_param_t *in_param, out_pkg_param_t *out_param);
int create_rename_pkg(struct hk_sb_info *sbi, const char *new_name,
                      obj_ref_dentry_t *ref, struct hk_inode_info_header *sih,
                      struct hk_inode_info_header *psih, struct hk_inode_info_header *npsih,
                      out_pkg_param_t *unlink_out_param, out_pkg_param_t *create_out_param);
int create_symlink_pkg(struct hk_sb_info *sbi, u16 mode, const char *name, const char *symname, u32 ino,
                       u64 symaddr, struct hk_inode_info_header *sih, struct hk_inode_info_header *psih,
                       out_pkg_param_t *data_out_param, out_pkg_param_t *create_out_param);

/* ======================= ANCHOR: cmt.c ========================= */
int hk_valid_hdr_background(struct super_block *sb, struct inode *inode, u64 blk_addr, u64 f_blk);
int hk_invalid_hdr_background(struct super_block *sb, struct inode *inode, u64 blk_addr, u64 f_blk);
int hk_valid_range_background(struct super_block *sb, struct inode *inode, struct hk_cmt_batch *batch);
void hk_start_cmt_workers(struct super_block *sb);
void hk_stop_cmt_workers(struct super_block *sb);
void hk_flush_cmt_inode_fast(struct super_block *sb, u64 ino);
void hk_flush_cmt_queue(struct super_block *sb);
struct hk_cmt_queue *hk_init_cmt_queue(struct super_block *sb, int nfecthers);
void hk_free_cmt_queue(struct hk_cmt_queue *cq);

/* ======================= ANCHOR: rebuild.c ========================= */
int hk_rebuild_inode(struct super_block *sb, struct hk_inode_info *si, u32 ino, bool build_blks);

/* ======================= ANCHOR: linix.c ========================= */
int linix_init(struct linix *ix, u64 num_slots);
int linix_destroy(struct linix *ix);
int linix_extend(struct linix *ix);
u64 linix_get(struct linix *ix, u64 index);
int linix_insert(struct linix *ix, u64 index, u64 blk_addr, bool extend);
int linix_delete(struct linix *ix, u64 index, u64 last_index, bool shrink);

/* ======================= ANCHOR: gc.c ========================= */
#if 0
int hk_friendly_gc(struct super_block *sb);
int hk_start_equalizer(struct super_block *sb);
int hk_terminal_equalizer(struct super_block *sb);
#endif

/* ======================= ANCHOR: stats.c ========================= */
void hk_get_timing_stats(void);
void hk_get_IO_stats(void);
void hk_clear_stats(struct super_block *sb);

/* ======================= ANCHOR: sysfs.c ========================= */
extern const char *proc_dirname;
extern struct proc_dir_entry *hk_proc_root;
void hk_sysfs_init(struct super_block *sb);
void hk_sysfs_exit(struct super_block *sb);


/* ======================= ANCHOR: Static Utils ========================= */
static inline int hk_get_cpuid(struct super_block *sb)
{
	struct hk_sb_info *sbi = HK_SB(sb);

	// return smp_processor_id() % sbi->cpus;
	// always allocate from the first cpu
	return 0;
}

#define BITS32_TO_BITS64(hi, lo) (((u64)(hi) << 32) | (lo))

static u64 inline get_pm_blk_addr(struct hk_sb_info *sbi, u32 blk)
{
    return (u64)sbi->virt_addr + ((u64)blk << HUNTER_BLK_SHIFT);
}

static u64 inline get_pm_entry_addr(struct hk_sb_info *sbi, u32 blk, u32 entrynr)
{
    return get_pm_blk_addr(sbi, blk) + ((u64)entrynr << HUNTER_MTA_SHIFT);
}

static u64 inline get_pm_addr(struct hk_sb_info *sbi, u64 offset)
{
    return (u64)sbi->virt_addr + offset;
}

static u64 inline get_pm_addr_by_data_ref(struct hk_sb_info *sbi, obj_ref_data_t *ref, u64 in_file_offset)
{
	BUG_ON(!ref);
	if (in_file_offset < ref->ofs) {
		return 0;
	}
	return get_pm_addr(sbi, ref->data_offset) + in_file_offset - ref->ofs;
}

static u64 inline get_pm_offset(struct hk_sb_info *sbi, u64 addr)
{
    return addr - (u64)sbi->virt_addr;
}

static u64 inline get_pm_blk_offset(struct hk_sb_info *sbi, u64 blk)
{
    return (blk << HUNTER_BLK_SHIFT);
}

static u64 inline get_pm_blk(struct hk_sb_info *sbi, u64 addr)
{
    return (u64)(get_pm_offset(sbi, addr) >> HUNTER_BLK_SHIFT);
}

static u64 inline get_layout_idx(struct hk_sb_info *sbi, u64 offset)
{
	u64 idx = (offset - get_pm_offset(sbi, sbi->pack_layout.fs_start)) / (sbi->per_layout_blks << HUNTER_BLK_SHIFT);
    return idx >= sbi->num_layout ? sbi->num_layout - 1 : idx;
}

static inline struct tl_allocator *get_tl_allocator(struct hk_sb_info *sbi, u64 offset)
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

static inline void use_layout(struct hk_layout_info* layout)
{
	mutex_lock(&layout->layout_lock);
}

static inline void unuse_layout(struct hk_layout_info* layout)
{
	mutex_unlock(&layout->layout_lock);
}

static inline void use_layout_id(struct super_block *sb, u64 id)
{
	struct hk_sb_info *sbi = HK_SB(sb);
	use_layout(&sbi->layouts[id]);
}

static inline void unuse_layout_id(struct super_block *sb, u64 id)
{
	struct hk_sb_info *sbi = HK_SB(sb);
	unuse_layout(&sbi->layouts[id]);
}

static inline void use_layout_for_addr(struct super_block *sb, u64 addr)
{
	int cpuid;
	struct hk_sb_info *sbi = HK_SB(sb);
    u64 size_per_layout = _round_down(sbi->d_size / sbi->num_layout, HK_PBLK_SZ(sbi));
    cpuid = (addr - sbi->d_addr) / size_per_layout;
	cpuid = cpuid >= sbi->num_layout ? cpuid - 1 : cpuid;
    use_layout_id(sb, cpuid);
}

static inline void unuse_layout_for_addr(struct super_block *sb, u64 addr)
{
	int cpuid;
	struct hk_sb_info *sbi = HK_SB(sb);
    u64 size_per_layout = _round_down(sbi->d_size / sbi->num_layout, HK_PBLK_SZ(sbi));
    cpuid = (addr - sbi->d_addr) / size_per_layout;
	cpuid = cpuid >= sbi->num_layout ? cpuid - 1 : cpuid;
    unuse_layout_id(sb, cpuid);
}

static inline void use_layout_for_hdr(struct super_block *sb, u64 hdr)
{
	struct hk_layout_info *layout;
	layout = sm_get_layout_by_hdr(sb, hdr);
	use_layout(layout);
}

static inline void unuse_layout_for_hdr(struct super_block *sb, u64 hdr)
{
	struct hk_layout_info *layout;
	layout = sm_get_layout_by_hdr(sb, hdr);
	unuse_layout(layout);
}

static inline void use_journal(struct super_block *sb, int txid)
{
	struct hk_sb_info *sbi = HK_SB(sb);
	mutex_lock(&sbi->norm_layout.j_locks[txid]);
}

static inline void unuse_journal(struct super_block *sb, int txid)
{
	struct hk_sb_info *sbi = HK_SB(sb);
	mutex_unlock(&sbi->norm_layout.j_locks[txid]);
}

static inline void use_nvm_inode(struct super_block *sb, u64 ino)
{
	struct hk_sb_info *sbi = HK_SB(sb);
	mutex_lock(&sbi->norm_layout.irange_locks[ino % sbi->cpus]);
}

static inline void unuse_nvm_inode(struct super_block *sb, u64 ino)
{
	struct hk_sb_info *sbi = HK_SB(sb);
	mutex_unlock(&sbi->norm_layout.irange_locks[ino % sbi->cpus]);
}

static inline void hk_sync_super(struct super_block *sb)
{
	struct hk_sb_info 	  *sbi = HK_SB(sb);
	struct hk_super_block *super = hk_get_super(sb, HUNTER_FIRST_SUPER_BLK);
	struct hk_super_block *super_redund = hk_get_super(sb, HUNTER_SECOND_SUPER_BLK);
	unsigned long 		  irq_flags = 0;

	hk_memunlock_super(sb, HUNTER_FIRST_SUPER_BLK, &irq_flags);
	memcpy_to_pmem_nocache((void *)super, (void *)sbi->hk_sb,
							HK_SB_SIZE(sbi));
	hk_memlock_super(sb, HUNTER_SECOND_SUPER_BLK, &irq_flags);
	PERSISTENT_BARRIER();
	
	hk_memunlock_super(sb, HUNTER_SECOND_SUPER_BLK, &irq_flags);
	memcpy_to_pmem_nocache((void *)super_redund, (void *)sbi->hk_sb,
							HK_SB_SIZE(sbi));
	hk_memlock_super(sb, HUNTER_SECOND_SUPER_BLK, &irq_flags);
	PERSISTENT_BARRIER();
}

/* Update checksum for the DRAM copy */
static inline void hk_update_super_crc(struct super_block *sb)
{
	struct hk_sb_info *sbi = HK_SB(sb);
	u32 			  crc = 0;

	sbi->hk_sb->s_wtime = cpu_to_le32(get_seconds());
	sbi->hk_sb->s_sum = 0;
	crc = hk_crc32c(~0, (__u8 *)sbi->hk_sb + sizeof(__le32),
			sizeof(struct hk_super_block) - sizeof(__le32) + sbi->hk_sb->s_private_data_len);
	sbi->hk_sb->s_sum = cpu_to_le32(crc);
}

static inline void ssleep_interruptible(unsigned int seconds)
{
	if (seconds > 0) {
		msleep_interruptible(seconds * 1000);
	}
}

#endif /* _HK_H */