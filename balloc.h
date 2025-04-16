#ifndef _WOFS_BALLOC_H_
#define _WOFS_BALLOC_H_

#include "wofs.h"

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
    struct tl_allocator allocator;
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

#endif /* _WOFS_BALLOC_H */