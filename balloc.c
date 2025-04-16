#include "wofs.h"

u64 get_version(struct wofs_sb_info *sbi)
{
    u64 tstamp;
    spin_lock(&sbi->norm_layout.ts_lock);
    tstamp = sbi->norm_layout.tstamp;
    spin_unlock(&sbi->norm_layout.ts_lock);
    return tstamp;
}

int up_version(struct wofs_sb_info *sbi)
{
    spin_lock(&sbi->norm_layout.ts_lock);
    sbi->norm_layout.tstamp++;
    spin_unlock(&sbi->norm_layout.ts_lock);
    return 0;
}

u64 wofs_prepare_layout(struct super_block *sb, int cpuid, u64 blks, enum wofs_layout_type type,
                      u64 *blks_prepared, bool zero)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_layout_info *layout = &sbi->layouts[cpuid];
    u64 target_addr = layout->layout_start;
    unsigned long irq_flags = 0;

    switch (type) {
    case LAYOUT_PACK: {
        tlalloc_param_t param;
        tl_allocator_t *allocator = &layout->allocator;
        int ret = 0;

        tl_build_alloc_param(&param, blks, TL_BLK);
        ret = tlalloc(allocator, &param);
        if (ret) {
            return 0;
        }

        wofs_dbgv("%s: alloc blk range: %llu - %llu\n", __func__, param._ret_rng.low, param._ret_rng.high);

        target_addr = get_pm_blk_addr(sbi, param._ret_rng.low);
        if (blks_prepared != NULL) {
            *blks_prepared = param._ret_allocated;
        }
        break;
    }
    default:
        wofs_dbgv("%s: not support args\n", __func__);
        return 0;
        break;
    }

    if (zero) {
        wofs_memunlock_range(sb, (void *)target_addr, blks * WOFS_PBLK_SZ(sbi), &irq_flags);
        memset_nt((void *)target_addr, 0, blks * WOFS_PBLK_SZ(sbi));
        wofs_memlock_range(sb, (void *)target_addr, blks * WOFS_PBLK_SZ(sbi), &irq_flags);
    }

    if (ENABLE_META_LOCAL(sb)) {
        if (!IS_ALIGNED(TRANS_ADDR_TO_OFS(sbi, target_addr), WOFS_LBLK_SZ(sbi))) {
            wofs_warn("%s: target_addr [%llu] is not aligned to BLOCK\n", __func__, TRANS_ADDR_TO_OFS(sbi, target_addr));
        }
    } else {
        if (!IS_ALIGNED(TRANS_ADDR_TO_OFS(sbi, target_addr), CACHELINE_SIZE)) {
            wofs_warn("%s: target_addr [%llu] is not aligned to CACHELINE\n", __func__, TRANS_ADDR_TO_OFS(sbi, target_addr));
        }
    }

    wofs_dbgv("%s: prepare addr 0x%llx, virt addr start @0x%llx", __func__, target_addr, sbi->virt_addr);

    return target_addr;
}

int wofs_alloc_blocks(struct super_block *sb, unsigned long *blks, bool zero, struct wofs_layout_prep *prep)
{
    struct wofs_layout_info *layout;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    int i, cpuid;
    int start_cpuid;
    u64 blks_prepared = 0;
    u64 target_addr;
    int tries = 0;
    INIT_TIMING(alloc_time);
    WOFS_START_TIMING(new_data_blocks_t, alloc_time);

    start_cpuid = wofs_get_cpuid(sb);

    prep->blks_prepared = 0;
    prep->cpuid = -1;
    prep->target_addr = 0;

    for (i = 0; i < sbi->num_layout; i++) {
        cpuid = (start_cpuid + i) % sbi->num_layout;
        layout = &sbi->layouts[cpuid];

        target_addr = wofs_prepare_layout(sb, cpuid, *blks, LAYOUT_PACK, &blks_prepared, zero);
        if (target_addr == 0) {
            continue;
        }

        prep->blks_prepared = blks_prepared;
        prep->cpuid = cpuid;
        prep->target_addr = target_addr;
        *blks -= blks_prepared;
        break;
    }

    WOFS_END_TIMING(new_data_blocks_t, alloc_time);
    return prep->blks_prepared == 0 ? -1 : 0;
}

unsigned long wofs_count_free_blocks(struct super_block *sb)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_layout_info *layout;
    unsigned long num_free_blocks = 0;
    int i;

    // FIXME

    return num_free_blocks;
}

int wofs_layouts_init(struct wofs_sb_info *sbi, int cpus)
{
    struct super_block *sb = sbi->sb;
    struct wofs_layout_info *layout;
    int cpuid;
    u64 size_per_layout;
    u64 blks_per_layout;
    int ret = 0;

    size_per_layout = _round_down(sbi->d_size / cpus, WOFS_PBLK_SZ(sbi));
    sbi->per_layout_blks = size_per_layout / WOFS_PBLK_SZ(sbi);
    sbi->num_layout = cpus;
    sbi->layouts = (struct wofs_layout_info *)kcalloc(cpus, sizeof(struct wofs_layout_info), GFP_KERNEL);
    if (sbi->layouts == NULL) {
        ret = -ENOMEM;
        goto out;
    }

    for (cpuid = 0; cpuid < cpus; cpuid++) {
        layout = &sbi->layouts[cpuid];
        layout->layout_start = sbi->d_addr + size_per_layout * cpuid;
        if (cpuid == cpus - 1) {
            size_per_layout = _round_down((sbi->d_size - cpuid * size_per_layout), WOFS_PBLK_SZ(sbi));
        }
        blks_per_layout = size_per_layout / WOFS_PBLK_SZ(sbi);
        layout->cpuid = cpuid;
        layout->layout_blks = blks_per_layout;
        layout->layout_end = layout->layout_start + size_per_layout;
        mutex_init(&layout->layout_lock);
        
        tl_alloc_init(&layout->allocator, cpuid, get_pm_blk(sbi, layout->layout_start), layout->layout_blks, WOFS_PBLK_SZ(sbi), WOFS_MTA_SIZE);
        
        wofs_dbgv("layout[%d]: 0x%llx-0x%llx, total_blks: %llu\n", cpuid, layout->layout_start, layout->layout_end, layout->layout_blks);
    }
out:
    return ret;
}

int wofs_layouts_free(struct wofs_sb_info *sbi)
{
    struct wofs_layout_info *layout;

    int cpuid;
    if (sbi->layouts) {
        for (cpuid = 0; cpuid < sbi->num_layout; cpuid++) {
            layout = &sbi->layouts[cpuid];
            tl_destory(&layout->allocator);
        }
        kfree(sbi->layouts);
    }
    return 0;
}