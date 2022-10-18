#ifndef _HK_CONFIG_H_
#define _HK_CONFIG_H_

#define HUNTER_SUPER_MAGIC 0x48554E54

/*
 * The HUNTER filesystem constants/structures
 */

/*
 * Mount flags
 */
#define HUNTER_MOUNT_PROTECT      0x000001 /* wprotect CR0.WP */
#define HUNTER_MOUNT_XATTR_USER   0x000002 /* Extended user attributes */
#define HUNTER_MOUNT_POSIX_ACL    0x000004 /* POSIX Access Control Lists */
#define HUNTER_MOUNT_DAX          0x000008 /* Direct Access */
#define HUNTER_MOUNT_ERRORS_CONT  0x000010 /* Continue on errors */
#define HUNTER_MOUNT_ERRORS_RO    0x000020 /* Remount fs ro on errors */
#define HUNTER_MOUNT_ERRORS_PANIC 0x000040 /* Panic on errors */
#define HUNTER_MOUNT_HUGEMMAP     0x000080 /* Huge mappings with mmap */
#define HUNTER_MOUNT_HUGEIOREMAP  0x000100 /* Huge mappings with ioremap */
#define HUNTER_MOUNT_FORMAT       0x000200 /* was FS formatted on mount? */
#define HUNTER_MOUNT_DATA_COW     0x000400 /* Copy-on-write for data integrity */
#define HUNTER_MOUNT_META_ASYNC   0x000800 /* Write metadata asynchronously */
#define HUNTER_MOUNT_META_LOCAL   0x001000 /* Reserving a continuous space to write meta */
#define HUNTER_MOUNT_META_PACK    0x002000 /* Pack meta (physically, logically) */
#define HUNTER_MOUNT_HISTORY_W    0x004000 /* History window for file open */
/*
 * Maximal count of links to a file
 */
#define HK_LINK_MAX 32000

#define POSSIBLE_MAX_CPU 1024

#define HK_MAX_LAYOUTS 64

#define PM_ACCESS_GRANU 256

/*
 * HUNTER CONFIGURATIONS
 */
#define HK_PBLK_SZ(sbi) sbi->pblk_sz
#define HK_LBLK_SZ(sbi) sbi->lblk_sz /* logic block size */
#define HK_NUM_INO (1024 * 1024)
#define HK_RG_SLOTS (1024 * 1024)
#define HK_RG_ENTY_SLOTS (4)
#define HK_LINIX_SLOTS (1024 * 256) /* related to init size */
#define HK_HISTORY_WINDOWS (1) /* for dynamic workloads */
#define HK_NAME_LEN 255
#define HK_HASH_BITS 6 /* for directory table */
#define HK_CMT_QUEUE_BITS 10 /* for commit queue */
// #define HK_CMT_TIME_INTERVAL 5 /* Default */
#define HK_CMT_MAX_PROCESS_BATCH (1024 * 256)
#define HK_CMT_WAKEUP_THRESHOLD  (1024 * 256)
#define HK_MAX_GAPS_INRAM 		 (1024 * 256)
#define HK_CMT_WORKER_NUM 4 /* for commit worker */
#define HK_JOURNAL_SIZE (4 * 1024)
#define HK_PERCORE_JSLOTS (1) /* per core journal slots */
#define HK_BLKS_SIZE(blks) (((blks) << 12) + ((blks) << 6))

/* ======================= Enhanced Configurations ========================= */

#define CONFIG_CMT_BACKGROUND /* enable background commit system */

#define CONFIG_PERCORE_IALLOCATOR /* enable per core inode allocator */

#define CONFIG_FINEGRAIN_JOURNAL /* enable fine grain-ed journal  */

#define CONFIG_DYNAMIC_WORKLOAD /* enable dynamic workload detection */

// #define CONFIG_ENABLE_EQUALIZER					/* enable layout equalizer */

// #define CONFIG_LAYOUT_TIGHT						/* enable tight layout */

#ifdef CONFIG_LAYOUT_TIGHT
#define HK_PBLK_SZ(sbi)          (PAGE_SIZE + sizeof(struct hk_header))
#endif

/* ======================= Write ordering ========================= */

#define CACHELINE_SIZE        (64)
#define CACHELINE_MASK        (~(CACHELINE_SIZE - 1))
#define CACHELINE_ALIGN(addr) (((addr) + CACHELINE_SIZE - 1) & CACHELINE_MASK)

static inline bool arch_has_clwb(void)
{
    return static_cpu_has(X86_FEATURE_CLWB);
}

extern int support_clwb;

#define _mm_clflush(addr)     \
    asm volatile("clflush %0" \
                 : "+m"(*(volatile char *)(addr)))
#define _mm_clflushopt(addr)              \
    asm volatile(".byte 0x66; clflush %0" \
                 : "+m"(*(volatile char *)(addr)))
#define _mm_clwb(addr)                     \
    asm volatile(".byte 0x66; xsaveopt %0" \
                 : "+m"(*(volatile char *)(addr)))

static inline void PERSISTENT_BARRIER(void)
{
    asm volatile("sfence\n"
                 :
                 :);
}

static inline void hk_flush_small_buffer(void *buf, uint32_t len, bool fence)
{
    uint32_t i;

    len = len + ((unsigned long)(buf) & (CACHELINE_SIZE - 1));
    for (i = 0; i < len; i += CACHELINE_SIZE)
        _mm_clflushopt(buf + i);
    /* Do a fence only if asked. We often don't need to do a fence
     * immediately after clflush because even if we get context switched
     * between clflush and subsequent fence, the context switch operation
     * provides implicit fence.
     */
    if (fence)
        PERSISTENT_BARRIER();
}

static inline void hk_flush_buffer(void *buf, uint32_t len, bool fence)
{
    uint32_t i;

    len = len + ((unsigned long)(buf) & (CACHELINE_SIZE - 1));
    if (support_clwb) {
        for (i = 0; i < len; i += CACHELINE_SIZE)
            _mm_clwb(buf + i);
    } else {
        for (i = 0; i < len; i += CACHELINE_SIZE)
            _mm_clflush(buf + i);
    }
    /* Do a fence only if asked. We often don't need to do a fence
     * immediately after clflush because even if we get context switched
     * between clflush and subsequent fence, the context switch operation
     * provides implicit fence.
     */
    if (fence)
        PERSISTENT_BARRIER();
}

/* ======================= GC static workers ========================= */
/* TODO: We might not need this */
#define HK_MAX_GC_SENDER 4
#define HK_MAX_GC_WRITER 2

#define HK_EQU_FACTOR 50

#endif /* _HK_CONFIG_H_ */