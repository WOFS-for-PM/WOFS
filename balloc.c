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

int wofs_find_gaps(struct super_block *sb, int cpuid)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_layout_info *layout = &sbi->layouts[cpuid];
    struct wofs_header *hdr;
    u64 addr;
    u64 blk;
    unsigned long irq_flags = 0;

    if (layout->num_gaps_indram != 0) {
        return -1;
    }

    wofs_memunlock_range(sb, (void *)sbi->norm_layout.sm_addr, sbi->norm_layout.sm_size, &irq_flags);
    traverse_layout_blks_reverse(addr, layout)
    {
        hdr = sm_get_hdr_by_addr(sb, addr);
        if (hdr->valid == HDR_INVALID) {
            blk = wofs_get_dblk_by_addr(sbi, addr);
            wofs_range_insert_value(sb, &layout->gaps_list, blk);
            layout->num_gaps_indram++;
            hdr->valid = HDR_PENDING;
            wofs_flush_buffer(hdr, sizeof(struct wofs_header), false);
        }
        if (layout->num_gaps_indram > WOFS_MAX_GAPS_INRAM) {
            break;
        }
    }
    wofs_memlock_range(sb, (void *)sbi->norm_layout.sm_addr, sbi->norm_layout.sm_size, &irq_flags);
    PERSISTENT_BARRIER();
    return 0;
}

u64 wofs_prepare_gap_in_layout(struct super_block *sb, int cpuid, u64 blks,
                             u64 *blks_prepared, bool zero)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_layout_info *layout = &sbi->layouts[cpuid];
    struct wofs_header *hdr;
    struct wofs_range_node *range;
    u64 blk_start;
    u64 addr;

    /* TODO: remove this from critical path */
    wofs_find_gaps(sb, cpuid);

    if (layout->num_gaps_indram == 0) {
        wofs_info("%s: No more invalid blks in cpuid: %d \n", __func__, cpuid);
        return 0;
    }

    blk_start = wofs_range_pop(&layout->gaps_list, &blks);
    if (!blk_start) {
        wofs_info("%s: No Gaps in %d\n", __func__, blk_start);
        BUG_ON(1);
    }
    *blks_prepared = blks;
    layout->num_gaps_indram -= blks;

    addr = wofs_get_addr_by_dblk(sbi, blk_start);
    return addr;
}

u64 wofs_prepare_layout(struct super_block *sb, int cpuid, u64 blks, enum wofs_layout_type type,
                      u64 *blks_prepared, bool zero)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_layout_info *layout = &sbi->layouts[cpuid];
    u64 target_addr = layout->layout_start;
    unsigned long irq_flags = 0;

    switch (type) {
    case LAYOUT_APPEND: {
        up_version(sbi);
        if (unlikely(!mutex_is_locked(&layout->layout_lock))) {
            wofs_info("%s: layout_lock is not locked\n", __func__);
            BUG_ON(1);
        }
        wofs_dbgv("%s: layout start @0x%llx, layout tail @0x%llx", __func__, target_addr, layout->atomic_counter);
        target_addr += layout->atomic_counter;

        if (unlikely(target_addr + (blks * WOFS_PBLK_SZ(sbi)) >= layout->layout_end)) {
            blks = (layout->layout_end - target_addr) / WOFS_PBLK_SZ(sbi);
        }

        if (unlikely(blks <= 0)) {
            return 0;
        }

        layout->atomic_counter += (blks * WOFS_PBLK_SZ(sbi));
        if (blks_prepared != NULL) {
            *blks_prepared = blks;
        }
        break;
    }
    case LAYOUT_GAP: {
        up_version(sbi);
        if (unlikely(!mutex_is_locked(&layout->layout_lock))) {
            wofs_info("%s: layout_lock is not locked\n", __func__);
            BUG_ON(1);
        }
        target_addr = wofs_prepare_gap_in_layout(sb, cpuid, blks, blks_prepared, zero);
        if (target_addr == 0) {
            return 0;
        }
        break;
    }
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

    if (ENABLE_META_PACK(sb)) {
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
    } else {
    retry:
        for (i = 0; i < sbi->num_layout; i++) {
            cpuid = (start_cpuid + i) % sbi->num_layout;
            layout = &sbi->layouts[cpuid];

            use_layout(layout);
            if (tries == 0) {
                target_addr = wofs_prepare_layout(sb, cpuid, *blks, LAYOUT_APPEND, &blks_prepared, zero);
            } else if (tries == 1) {
                target_addr = wofs_prepare_layout(sb, cpuid, *blks, LAYOUT_GAP, &blks_prepared, zero);
            }
            unuse_layout(layout);

            if (target_addr == 0) {
                continue;
            }

            prep->blks_prepared = blks_prepared;
            prep->cpuid = cpuid;
            prep->target_addr = target_addr;
            *blks -= blks_prepared;
            break;
        }
        if (tries < 1) {
            tries++;
            if (prep->target_addr == 0) {
                wofs_info("%s: No space in layout, try to use gap\n", __func__);
                goto retry;
            }
        }
    }
    WOFS_END_TIMING(new_data_blocks_t, alloc_time);
    return prep->blks_prepared == 0 ? -1 : 0;
}

int wofs_release_layout(struct super_block *sb, int cpuid, u64 blks, bool rls_all)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_layout_info *layout = &sbi->layouts[cpuid];

    if (rls_all) {
        layout->atomic_counter = 0;
    } else {
        layout->atomic_counter -= (blks * WOFS_PBLK_SZ(sbi));
    }

    return 0;
}

unsigned long wofs_count_free_blocks(struct super_block *sb)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_layout_info *layout;
    unsigned long num_free_blocks = 0;
    int i;

    if (ENABLE_META_PACK(sb)) {
        /* Do Nothing */
    } else {
        for (i = 0; i < sbi->cpus; i++) {
            layout = &sbi->layouts[i];
            use_layout(layout);
            num_free_blocks += (layout->ind.free_blks + layout->ind.invalid_blks);
            unuse_layout(layout);
        }
    }

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
        if (ENABLE_META_PACK(sb)) {
            tl_alloc_init(&layout->allocator, cpuid, get_pm_blk(sbi, layout->layout_start), layout->layout_blks, WOFS_PBLK_SZ(sbi), WOFS_MTA_SIZE);
        } else {
            layout->atomic_counter = 0;
            layout->num_gaps_indram = 0;
            INIT_LIST_HEAD(&layout->gaps_list);
        }
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
            if (ENABLE_META_PACK(sbi->sb)) {
                tl_destory(&layout->allocator);
            } else {
                wofs_range_free_all(&layout->gaps_list);
            }
        }
        kfree(sbi->layouts);
    }
    return 0;
}