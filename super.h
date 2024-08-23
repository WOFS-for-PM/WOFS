#ifndef _HK_SUPER_H
#define _HK_SUPER_H
#include "hunter.h"
/*
 * Structure of the HUNTER super block in PMEM
 *
 * The fields are partitioned into static and dynamic fields. The static fields
 * never change after file system creation. This was primarily done because
 * hk_get_block() returns NULL if the block offset is 0 (helps in catching
 * bugs). So if we modify any field using journaling (for consistency), we
 * will have to modify s_sum which is at offset 0. So journaling code fails.
 * This (static+dynamic fields) is a temporary solution and can be avoided
 * once the file system becomes stable and hk_get_block() returns correct
 * pointers even for offset 0.
 */
struct hk_super_block {
    /* static fields. they never change after file system creation.
     * checksum only validates up to s_start_dynamic field below
     */
    __le32 s_sum;   /* checksum of this sb plus private data appended at the end of this sb */
    __le32 s_magic; /* magic signature */
    __le32 s_padding32;
    __le32 s_blocksize;     /* blocksize in bytes */
    __le64 s_size;          /* total size of fs in bytes */
    char s_volume_name[16]; /* volume name */

    /* all the dynamic fields should go here */
    /* s_mtime and s_wtime should be together and their order should not be
     * changed. we use an 8 byte write to update both of them atomically
     */
    __le32 s_mtime; /* mount time */
    __le32 s_wtime; /* write time */

    __le32 s_last_layout;  /* 0 for lfs, 1 for local, 2 for pack, cannot be changed now */
    __le32 s_valid_umount; /* is valid umount ? */

    __le64 s_private_data;     /* offset of private data relative to current super block */
    __le64 s_private_data_len; /* private data len */

} __attribute((__packed__));

struct hk_normal_data {
    __le64 s_tstamp; /* time stemp */
    struct {
        __le64 s_atomic_counter;
        struct {
            __le64 valid_blks;
            __le64 invalid_blks;
            __le64 free_blks;
            __le64 prep_blks;
            __le64 total_blks;
        } s_ind;
    } s_layout[POSSIBLE_MAX_CPU];
};

struct hk_pack_data {
    u64 s_vtail;
};

#define HK_SB_SIZE(sbi) round_up(sizeof(struct hk_super_block) + sbi->hk_sb->s_private_data_len, HK_LBLK_SZ(sbi)) /* must be power of two */

#define HUNTER_BLK_SIZE  (4 * 1024)
#define HUNTER_MTA_SIZE  (64) // 64B grained
#define HUNTER_BLK_SHIFT (12)
#define HUNTER_MTA_SHIFT (6)

#define HK_ROOT_INO (0)
#define HK_RESV_NUM (1)
/*
 * hk super-block data in DRAM
 */
struct hk_sb_info {
    struct super_block *sb;        /* VFS super block */
    struct hk_super_block *hk_sb;  /* DRAM copy of primary SB (i.e., First SB) */
    struct block_device *s_bdev;
    struct dax_device *s_dax_dev;
    /*
     * base physical and virtual address of hk (which is also
     * the pointer to the super block)
     */
    phys_addr_t phys_addr;
    void *virt_addr;

    unsigned long num_blocks;

    /* Mount options */
    unsigned long bpi;
    unsigned long blocksize;
    unsigned long initsize;
    unsigned long s_mount_opt;
    kuid_t uid;   /* Mount uid for root directory */
    kgid_t gid;   /* Mount gid for root directory */
    umode_t mode; /* Mount mode for root directory */
    atomic_t next_generation;
    /* inode tracking */
    unsigned long s_inodes_used_count;

    struct mutex s_lock; /* protects the SB's buffer-head */

    int cpus;
    struct proc_dir_entry *s_proc;

    /* DAX-mmap snapshot structures */
    struct mutex vma_mutex;
    struct list_head mmap_sih_list;

    u32 pblk_sz;
    u32 lblk_sz;

    /* data */
    u64 d_addr;
    u64 d_size;
    u64 d_blks;

    /* metadata-related */
    u64 m_addr;
    u64 m_size;

    /* misc */
    union {
        /* for normal layout */
        struct {
            u64 tstamp;
            spinlock_t ts_lock; /* Time stamp lock */

            /* inode table */
            u64 ino_tab_addr;
            u64 ino_tab_slots;
            u64 ino_tab_size;

            /* summary table */
            u64 sm_addr;
            u64 sm_slots;
            u64 sm_size;

            /* transcation table */
            u64 j_addr;
            u64 j_slots;
            u64 j_size;
            struct mutex *j_locks;

            /* inode-region (attr log) table */
            u64 rg_addr;
            u64 rg_slots;
            u64 rg_size;

            /* for inode management */
            struct mutex *irange_locks; /* For In-NVMM Inode Lock */
        } norm_layout;
        /* for pack layout */
        struct {
            /* bitmaps for saving packages allocation info */
            u64 bm_start;
            u64 bm_size;
            u64 fs_start;
            u64 tl_per_type_bm_reserved_blks;
            atomic64_t vtail;
            struct obj_mgr *obj_mgr;
            struct hk_inode_info_header *rih; /* root header */
        } pack_layout;
    };

    /* for write-control */
    atomic64_t num_writers;

    /* for read-ahead */
    size_t ra_win;
    atomic64_t num_readers;

    /* per cpu structure */
    struct hk_layout_info *layouts;
    u32 num_layout;
    u64 per_layout_blks; /* aligned blks */

    /* for background cmt */
    struct hk_cmt_queue *cq;
    struct task_struct *cmt_workers[HK_CMT_WORKER_NUM];
    int wake_up_interval;

    /* 32-bits per-core ino allocator */
    struct inode_mgr *inode_mgr;

    /* for dynamic workload */
    struct hk_dym_wkld dw;

// #ifdef AGING_WORKLOAD_SIZE
//     size_t aging_pos;
//     size_t recover_blks;
//     size_t counter;
// #endif
};

static u64 inline hk_inc_and_get_vtail(struct hk_sb_info *sbi)
{
    return (u64)atomic64_add_return(1, &sbi->pack_layout.vtail);
}

static inline struct hk_sb_info *HK_SB(struct super_block *sb)
{
    return sb->s_fs_info;
}

/* If this is part of a read-modify-write of the super block,
 * hk_memunlock_super() before calling!
 */
static inline struct hk_super_block *hk_get_super(struct super_block *sb, int n)
{
    struct hk_sb_info *sbi = HK_SB(sb);

    return n == HUNTER_FIRST_SUPER_BLK ? (struct hk_super_block *)sbi->virt_addr : (sbi->virt_addr + HK_SB_SIZE(sbi));
}

/* Update the crc32c value by appending a 64b data word. */
#define hk_crc32c_qword(qword, crc)           \
    do {                                      \
        asm volatile("crc32q %1, %0"          \
                     : "=r"(crc)              \
                     : "r"(qword), "0"(crc)); \
    } while (0)

static inline u32 hk_crc32c(u32 crc, const u8 *data, size_t len)
{
    u8 *ptr = (u8 *)data;
    u64 acc = crc; /* accumulator, crc32c value in lower 32b */
    u32 csum;

    /* x86 instruction crc32 is part of SSE-4.2 */
    if (static_cpu_has(X86_FEATURE_XMM4_2)) {
        /* This inline assembly implementation should be equivalent
         * to the kernel's crc32c_intel_le_hw() function used by
         * crc32c(), but this performs better on test machines.
         */
        while (len > 8) {
            asm volatile(/* 64b quad words */
                         "crc32q (%1), %0"
                         : "=r"(acc)
                         : "r"(ptr), "0"(acc));
            ptr += 8;
            len -= 8;
        }

        while (len > 0) {
            asm volatile(/* trailing bytes */
                         "crc32b (%1), %0"
                         : "=r"(acc)
                         : "r"(ptr), "0"(acc));
            ptr++;
            len--;
        }

        csum = (u32)acc;
    } else {
        /* The kernel's crc32c() function should also detect and use the
         * crc32 instruction of SSE-4.2. But calling in to this function
         * is about 3x to 5x slower than the inline assembly version on
         * some test machines.
         */
        csum = crc32c(crc, data, len);
    }

    return csum;
}

#endif /* _HK_SUPER_H */
