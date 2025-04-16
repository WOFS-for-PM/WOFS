#ifndef _WOFS_CONFIG_H_
#define _WOFS_CONFIG_H_

/*
 * The WOFS filesystem constants/structures
 */
#define WOFS_SUPER_BLKS       2
#define WOFS_FIRST_SUPER_BLK  0
#define WOFS_SECOND_SUPER_BLK 1

#define WOFS_SUPER_MAGIC     0x48554E54 /* HUNT */
#define WOFS_OBJ_MAGIC       0x484F424A /* HOBJ */
#define WOFS_UNO_MAGIC       0x48504B48 /* HUNO */
#define WOFS_MAX_NAME_LEN    (128 - 36)
#define WOFS_VALID_UNMOUNT   0xFFFFFFFF
#define WOFS_INVALID_UNMOUNT 0x00000000
#define WOFS_ROOT_INO        0

/*
 * Mount flags
 */
#define WOFS_MOUNT_PROTECT      0x000001 /* wprotect CR0.WP */
#define WOFS_MOUNT_XATTR_USER   0x000002 /* Extended user attributes */
#define WOFS_MOUNT_POSIX_ACL    0x000004 /* POSIX Access Control Lists */
#define WOFS_MOUNT_DAX          0x000008 /* Direct Access */
#define WOFS_MOUNT_ERRORS_CONT  0x000010 /* Continue on errors */
#define WOFS_MOUNT_ERRORS_RO    0x000020 /* Remount fs ro on errors */
#define WOFS_MOUNT_ERRORS_PANIC 0x000040 /* Panic on errors */
#define WOFS_MOUNT_HUGEMMAP     0x000080 /* Huge mappings with mmap */
#define WOFS_MOUNT_HUGEIOREMAP  0x000100 /* Huge mappings with ioremap */
#define WOFS_MOUNT_FORMAT       0x000200 /* was FS formatted on mount? */
#define WOFS_MOUNT_DATA_COW     0x000400 /* Copy-on-write for data integrity */
#define WOFS_MOUNT_META_ASYNC   0x000800 /* Write metadata asynchronously */
#define WOFS_MOUNT_META_LOCAL   0x001000 /* Reserving a continuous space to write meta */
#define WOFS_MOUNT_META_LFS     0x002000 /* Append metadata like LFS */
#define WOFS_MOUNT_META_PACK    0x004000 /* Pack meta (physically, logically). i.e., WRITE-ONCE */
#define WOFS_MOUNT_HISTORY_W    0x008000 /* History window for file open */

/*
 * Maximal count of links to a file
 */
#define WOFS_LINK_MAX      32000
#define POSSIBLE_MAX_CPU 1024
#define WOFS_MAX_LAYOUTS   64
#define PM_ACCESS_GRANU  256

/*
 * WOFS CONFIGURATIONS
 */
#define WOFS_PBLK_SZ(sbi)          sbi->pblk_sz
#define WOFS_LBLK_SZ(sbi)          sbi->lblk_sz /* logic block size */
#define WOFS_NUM_INO               (1024 * 1024)
#define WOFS_RG_SLOTS              (1024 * 1024)
#define WOFS_RG_ENTY_SLOTS         (4)
#define WOFS_MLIST_INST_MAXRETRIES (5)
#define WOFS_EXTEND_NUM_BLOCKS     (512)        /* for optimizing append/sequntial write */
#define WOFS_LINIX_SLOTS           (1024 * 256) /* related to init size */
#define WOFS_HISTORY_WINDOWS       (1)          /* for dynamic workloads */
#define WOFS_NAME_LEN              (128 - 36)
#define WOFS_HASH_BITS7            7  /* for those long period hash table */
#define WOFS_HASH_BITS3            3  /* for those frequent creating hash table */
#define WOFS_CMT_QUEUE_BITS        10 /* for commit queue */
#define WOFS_CMT_MAX_PROCESS_BATCH (1024 * 256)
#define WOFS_CMT_WAKEUP_THRESHOLD  (WOFS_CMT_MAX_PROCESS_BATCH * 2)
#define WOFS_MAX_GAPS_INRAM        (1024 * 256)
#define WOFS_CMT_WORKER_NUM        4 /* for commit worker */
#define WOFS_JOURNAL_SIZE          (4 * 1024)
#define WOFS_PERCORE_JSLOTS        (1) /* per core journal slots */
#define WOFS_READAHEAD_WINDOW      (16 * 1024)
#define WOFS_RESCUE_WORKERS        8  /* for failure recovery */

/* ======================= Enhanced Configurations ========================= */
#define CONFIG_CMT_BACKGROUND     /* enable background commit system */
#define CONFIG_PERCORE_IALLOCATOR /* enable per core inode allocator */
#define CONFIG_FINEGRAIN_JOURNAL  /* enable fine grain-ed journal  */
#define CONFIG_DYNAMIC_WORKLOAD   /* enable dynamic workload detection */
// #define CONFIG_ENABLE_EQUALIZER					/* enable layout equalizer */
// #define CONFIG_LAYOUT_TIGHT						/* enable tight layout */

#ifdef CONFIG_LAYOUT_TIGHT
#define WOFS_PBLK_SZ(sbi) (PAGE_SIZE + sizeof(struct wofs_header))
#endif

/* ======================= Write ordering ========================= */

#define CACHELINE_SIZE        (64)
#define CACHELINE_MASK        (~(CACHELINE_SIZE - 1))
#define CACHELINE_ALIGN(addr) (((addr) + CACHELINE_SIZE - 1) & CACHELINE_MASK)

static inline bool arch_has_clwb(void)
{
    return static_cpu_has(X86_FEATURE_CLWB);
}

static inline bool arch_has_avx512(void)
{
	return boot_cpu_has(X86_FEATURE_AVX2) &&
		boot_cpu_has(X86_FEATURE_AVX) &&
		boot_cpu_has(X86_FEATURE_AVX512F) &&
		boot_cpu_has(X86_FEATURE_AVX512BW) &&
		boot_cpu_has(X86_FEATURE_AVX512VL) &&
		boot_cpu_has(X86_FEATURE_AVX512DQ);
}

extern int support_clwb;
extern int support_avx;

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

static inline void MEMORY_BARRIER(void)
{
    asm volatile("mfence\n"
                 :
                 :);
}

static inline void wofs_flush_small_buffer(void *buf, uint32_t len, bool fence)
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

static inline void wofs_flush_buffer(void *buf, uint32_t len, bool fence)
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

#if 0
/* ======================= GC static workers ========================= */
/* TODO: We might not need this */
#define WOFS_MAX_GC_SENDER 4
#define WOFS_MAX_GC_WRITER 2

#define WOFS_EQU_FACTOR 50
#endif

#endif /* _WOFS_CONFIG_H_ */