#ifndef _WOFS_BALLOC_H_
#define _WOFS_BALLOC_H_

#include "wofs.h"

enum wofs_ind_upt_type {
    VALIDATE_BLK = 0,
    INVALIDATE_BLK,
    PREP_LAYOUT_REMOVE,
    PREP_LAYOUT_APPEND,
    PREP_LAYOUT_GAP,
    FREE_LAYOUT
};

struct wofs_indicator {
    u64 valid_blks;   //! Valid blks => hdr is valid
    u64 invalid_blks; //! Invalid blks => hdr is valid and in the boundary of atomic counter
    u64 free_blks;    //! Free blks => behind the boundary of atomic counter
    u64 prep_blks;    //! Preparing blks => Prepared Blks
    u64 total_blks;
};

enum wofs_layout_type {
    LAYOUT_APPEND = 0,
    LAYOUT_GAP,
    /* for pack, i.e., write-once layout */
    LAYOUT_PACK
};

struct wofs_layout_info {
    struct mutex layout_lock;
    u32 cpuid;
    u64 layout_start;
    u64 layout_end;
    u64 layout_blks;
    union {
        struct {
            u64 atomic_counter;
            u64 num_gaps_indram;
            struct list_head gaps_list;
            struct wofs_indicator ind;
        };
        struct {
            struct tl_allocator allocator;
        };
    };
};

struct wofs_layout_prep {
    int cpuid;
    u64 target_addr;
    u64 blks_prepared;
    u64 blks_prep_to_use;
};

struct wofs_layout_preps {
    bool is_enough_space;
    u32 num_layout;
    u32 idx;
    struct wofs_layout_prep preps[WOFS_MAX_LAYOUTS];
};

#define traverse_layout_blks(addr, layout)         for (addr = layout->layout_start; addr < layout->layout_start + layout->atomic_counter; addr += WOFS_PBLK_SZ(sbi))
#define traverse_layout_blks_reverse(addr, layout) for (addr = layout->layout_start + layout->atomic_counter - WOFS_PBLK_SZ(sbi); addr >= layout->layout_start; addr -= WOFS_PBLK_SZ(sbi))
#define GET_LAST_BLK_FROM_LAYOUT(layout)           (layout->atomic_counter + layout->layout_start - WOFS_PBLK_SZ(sbi))
#endif /* _WOFS_BALLOC_H */