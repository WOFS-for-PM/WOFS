#include "hunter.h"

u64 get_version(struct hk_sb_info *sbi)
{
    u64 tstamp;
    spin_lock(&sbi->ts_lock);
    tstamp = sbi->tstamp;
    spin_unlock(&sbi->ts_lock);
    return tstamp;
}

int up_version(struct hk_sb_info *sbi)
{
    spin_lock(&sbi->ts_lock);
    sbi->tstamp++;
    spin_unlock(&sbi->ts_lock);
    return 0;
}

int hk_find_gaps(struct super_block *sb, int cpuid)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_layout_info *layout = &sbi->layouts[cpuid];
    struct hk_header *hdr;
    u64 addr;
    u64 blk;
    unsigned long irq_flags = 0;

    if (layout->num_gaps_indram != 0) {
        return -1;
    }
    
    hk_memunlock_range(sb, (void *)sbi->sm_addr, sbi->sm_size, &irq_flags);
    traverse_layout_blks_reverse(addr, layout)
    {
        hdr = sm_get_hdr_by_addr(sb, addr);
        if (hdr->valid == HDR_INVALID) {
            blk = hk_get_dblk_by_addr(sbi, addr);
            hk_range_insert_value(sb, &layout->gaps_list, blk);
            layout->num_gaps_indram++;
            hdr->valid = HDR_PENDING;
            hk_flush_buffer(hdr, sizeof(struct hk_header), false);
        }
        if (layout->num_gaps_indram > HK_MAX_GAPS_INRAM) {
            break;
        }
    }
    hk_memlock_range(sb, (void *)sbi->sm_addr, sbi->sm_size, &irq_flags);
    PERSISTENT_BARRIER();
    return 0;
}

u64 hk_prepare_gap_in_layout(struct super_block *sb, int cpuid, u64 blks,
                             u64 *blks_prepared, bool zero)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_layout_info *layout = &sbi->layouts[cpuid];
    struct hk_header *hdr;
    struct hk_range_node *range;
    u64 blk_start;
    u64 addr;
     
    /* TODO: remove this from critical path */
    hk_find_gaps(sb, cpuid);

    if (layout->num_gaps_indram == 0) {
        hk_info("%s: No more invalid blks in cpuid: %d \n", __func__, cpuid);
        return 0;
    }
    
    blk_start = hk_range_pop(&layout->gaps_list, &blks);
    if (!blk_start) {
        hk_info("%s: No Gaps in %d\n", __func__, blk_start);
        BUG_ON(1);
    }
    *blks_prepared = blks;
    layout->num_gaps_indram -= blks;

    addr = hk_get_addr_by_dblk(sbi, blk_start);
    return addr;
}

u64 hk_prepare_layout(struct super_block *sb, int cpuid, u64 blks, enum hk_layout_type type,
                      u64 *blks_prepared, bool zero)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_layout_info *layout = &sbi->layouts[cpuid];
    u64 target_addr = layout->layout_start;
    unsigned long irq_flags = 0;

    if (unlikely(!mutex_is_locked(&layout->layout_lock))) {
        hk_info("%s: layout_lock is not locked\n", __func__);
        BUG_ON(1);
    }

    up_version(sbi);
    if (likely(type == LAYOUT_APPEND)) {
        hk_dbgv("%s: layout start @0x%llx, layout tail @0x%llx", __func__, target_addr, layout->atomic_counter);
        target_addr += layout->atomic_counter;

        if (unlikely(target_addr + (blks * HK_PBLK_SZ) >= layout->layout_end)) {
            blks = (layout->layout_end - target_addr) / HK_PBLK_SZ;
        }

        if (unlikely(blks <= 0)) {
            return 0;
        }

        layout->atomic_counter += (blks * HK_PBLK_SZ);
        if (blks_prepared != NULL) {
            *blks_prepared = blks;
        }
    } else if (type == LAYOUT_GAP) {
        target_addr = hk_prepare_gap_in_layout(sb, cpuid, blks, blks_prepared, zero);
        if (target_addr == 0) {
            return 0;
        }
    } else {
        hk_dbgv("%s: not support args\n", __func__);
        return 0;
    }

    if (zero) {
        hk_memunlock_range(sb, (void *)target_addr, blks * HK_PBLK_SZ, &irq_flags);
        memset_nt((void *)target_addr, 0, blks * HK_PBLK_SZ);
        hk_memlock_range(sb, (void *)target_addr, blks * HK_PBLK_SZ, &irq_flags);
    }

    if (test_opt(sb, META_LOCAL)) {
        if (!IS_ALIGNED(TRANS_ADDR_TO_OFS(sbi, target_addr), HK_LBLK_SZ)) {
            hk_warn("%s: target_addr [%llu] is not aligned to BLOCK\n", __func__, TRANS_ADDR_TO_OFS(sbi, target_addr));
        }
    } else {
        if (!IS_ALIGNED(TRANS_ADDR_TO_OFS(sbi, target_addr), CACHELINE_SIZE)) {
            hk_warn("%s: target_addr [%llu] is not aligned to CACHELINE\n", __func__, TRANS_ADDR_TO_OFS(sbi, target_addr));
        }
    }

    hk_dbgv("%s: prepare addr 0x%llx, virt addr start @0x%llx", __func__, target_addr, sbi->virt_addr);

    return target_addr;
}

int hk_alloc_blocks(struct super_block *sb, unsigned long *blks, bool zero, struct hk_layout_prep *prep)
{
    struct hk_layout_info *layout;
    struct hk_sb_info *sbi = HK_SB(sb);
    int i, cpuid;
    int start_cpuid;
    u64 blks_prepared = 0;
    u64 target_addr;
    int tries = 0;
    INIT_TIMING(alloc_time);
    HK_START_TIMING(new_data_blocks_t, alloc_time);

    start_cpuid = hk_get_cpuid(sb);

    prep->blks_prepared = 0;
    prep->cpuid = -1;
    prep->target_addr = 0;

retry:
    for (i = 0; i < sbi->num_layout; i++) {
        cpuid = (start_cpuid + i) % sbi->num_layout;
        layout = &sbi->layouts[cpuid];

        use_layout(layout);
        if (tries == 0) {
            target_addr = hk_prepare_layout(sb, cpuid, *blks, LAYOUT_APPEND, &blks_prepared, zero);
        } else if (tries == 1) {
            target_addr = hk_prepare_layout(sb, cpuid, *blks, LAYOUT_GAP, &blks_prepared, zero);
        }
        unuse_layout(layout);

        if (target_addr == 0) {
            continue;
        }

        prep->blks_prepared = blks_prepared;
        prep->cpuid = cpuid;
        prep->target_addr = target_addr;
        *blks = *blks - blks_prepared;
        break;
    }
    if (tries < 1) {
        tries++;
        if (prep->target_addr == 0) {
            hk_info("%s: No space in layout, try to use gap\n", __func__);
            goto retry;
        }
    }
    HK_END_TIMING(new_data_blocks_t, alloc_time);
    return prep->blks_prepared == 0 ? -1 : 0;
}

// int hk_prepare_layouts(struct super_block *sb, u32 blks, bool zero, struct hk_layout_preps *preps)
// {
//     struct hk_layout_info *layout;
//     struct hk_sb_info *sbi = HK_SB(sb);
//     int cpuid;
//     int start_cpuid;
//     u64 blks_prepared = 0;
//     u64 target_addr;

//     preps->num_layout = 0;
//     preps->is_enough_space = false;
//     preps->idx = 0;

//     start_cpuid = hk_get_cpuid(sb);
//     cpuid = start_cpuid;

//     for (; cpuid < sbi->num_layout; cpuid++) {
//         layout = &sbi->layouts[cpuid];

//         use_layout(layout);
//         target_addr = hk_prepare_layout(sb, cpuid, blks, LAYOUT_APPEND, &blks_prepared, zero);
//         unuse_layout(layout);

//         if (target_addr == 0) {
//             continue;
//         }

//         preps->preps[preps->num_layout].blks_prepared = blks_prepared;
//         preps->preps[preps->num_layout].cpuid = cpuid;
//         preps->preps[preps->num_layout].target_addr = target_addr;

//         preps->num_layout++;

//         blks -= blks_prepared;
//         if (blks == 0) {
//             preps->is_enough_space = true;
//             return 0;
//         }
//     }

//     for (cpuid = 0; cpuid < start_cpuid; cpuid++) {
//         layout = &sbi->layouts[cpuid];

//         use_layout(layout);
//         target_addr = hk_prepare_layout(sb, cpuid, blks, LAYOUT_APPEND, &blks_prepared, zero);
//         unuse_layout(layout);

//         if (target_addr == 0) {
//             continue;
//         }

//         preps->preps[preps->num_layout].blks_prepared = blks_prepared;
//         preps->preps[preps->num_layout].cpuid = cpuid;
//         preps->preps[preps->num_layout].target_addr = target_addr;

//         preps->num_layout++;

//         blks -= blks_prepared;
//         if (blks == 0) {
//             preps->is_enough_space = true;
//             return 0;
//         }
//     }

//     preps->is_enough_space = false;

//     return 0;
// }

// void hk_trv_prepared_layouts_init(struct hk_layout_preps *preps)
// {
//     preps->idx = 0;
// }

// struct hk_layout_prep *hk_trv_prepared_layouts(struct super_block *sb, struct hk_layout_preps *preps)
// {
//     int i;
//     int cpuid;
//     struct hk_layout_prep *prep = NULL;
//     u64 target_addr;

//     if (preps->idx >= preps->num_layout) {
//         return NULL;
//     }

//     prep = &preps->preps[preps->idx];
//     preps->idx++;

//     return prep;
// }

// u64 hk_rollback_layouts(struct super_block *sb, struct hk_layout_preps *preps)
// {
//     struct hk_sb_info *sbi = HK_SB(sb);
//     struct hk_layout_prep *prep;
//     struct hk_layout_info *layout;
//     u64 blk_start, blk_end;
//     u64 blks_rolledback = 0;

//     hk_trv_prepared_layouts_init(preps);

//     while (prep = hk_trv_prepared_layouts(sb, preps)) {
//         blk_start = hk_get_dblk_by_addr(sbi, prep->target_addr);
//         blk_end = blk_start + prep->blks_prepared - 1;
//         layout = &sbi->layouts[prep->cpuid];

//         use_layout(layout);
//         hk_range_remove_range(sb, &layout->prep_list, blk_start, blk_end);
//         ind_update(&layout->ind, PREP_LAYOUT_REMOVE, prep->blks_prepared);
//         blks_rolledback += prep->blks_prepared;
//         unuse_layout(layout);
//     }

//     return blks_rolledback;
// }

// /* same to hk_prepare_layouts: using LAYOUT_GAP instead */
// void hk_prepare_gap(struct super_block *sb, bool zero, struct hk_layout_prep *prep)
// {
//     u64 target_addr = 0;
//     struct hk_sb_info *sbi = HK_SB(sb);
//     struct hk_layout_info *layout;
//     int cpuid;
//     int start_cpuid;

//     start_cpuid = hk_get_cpuid(sb);
//     cpuid = start_cpuid;

//     prep->target_addr = 0;
//     prep->blks_prepared = 0;
//     prep->cpuid = -1;

//     for (; cpuid < sbi->num_layout; cpuid++) {
//         layout = &sbi->layouts[cpuid];

//         use_layout(layout);
//         target_addr = hk_prepare_layout(sb, cpuid, 1, LAYOUT_GAP, NULL, zero);
//         unuse_layout(layout);

//         if (target_addr == 0) {
//             continue;
//         } else {
//             prep->cpuid = cpuid;
//             prep->blks_prepared = 1;
//             prep->target_addr = target_addr;
//         }
//     }

//     for (cpuid = 0; cpuid < start_cpuid; cpuid++) {
//         layout = &sbi->layouts[cpuid];

//         use_layout(layout);
//         target_addr = hk_prepare_layout(sb, cpuid, 1, LAYOUT_GAP, NULL, zero);
//         unuse_layout(layout);

//         if (target_addr == 0) {
//             continue;
//         } else {
//             prep->cpuid = cpuid;
//             prep->blks_prepared = 1;
//             prep->target_addr = target_addr;
//         }
//     }
// }

int hk_release_layout(struct super_block *sb, int cpuid, u64 blks, bool rls_all)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_layout_info *layout = &sbi->layouts[cpuid];

    if (rls_all) {
        layout->atomic_counter = 0;
    } else {
        layout->atomic_counter -= (blks * HK_PBLK_SZ);
    }

    return 0;
}

unsigned long hk_count_free_blocks(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_layout_info *layout;
    unsigned long num_free_blocks = 0;
    int i;

    for (i = 0; i < sbi->cpus; i++) {
        layout = &sbi->layouts[i];
        use_layout(layout);
        num_free_blocks += (layout->ind.free_blks + layout->ind.invalid_blks);
        unuse_layout(layout);
    }

    return num_free_blocks;
}

int hk_layouts_init(struct hk_sb_info *sbi, int cpus)
{
    struct super_block *sb = sbi->sb;
    struct hk_layout_info *layout;
    int cpuid;
    u64 size_per_layout;
    u64 blks_per_layout;
    int ret = 0;

    size_per_layout = _round_down(sbi->d_size / cpus, HK_PBLK_SZ);
    sbi->num_layout = cpus;
    sbi->layouts = (struct hk_layout_info *)kcalloc(cpus, sizeof(struct hk_layout_info), GFP_KERNEL);
    if (sbi->layouts == NULL) {
        ret = -ENOMEM;
        goto out;
    }

    for (cpuid = 0; cpuid < cpus; cpuid++) {
        layout = &sbi->layouts[cpuid];
        layout->layout_start = sbi->d_addr + size_per_layout * cpuid;
        if (cpuid == cpus - 1) {
            size_per_layout = _round_down((sbi->d_size - cpuid * size_per_layout), HK_PBLK_SZ);
        }
        blks_per_layout = size_per_layout / HK_PBLK_SZ;
        layout->atomic_counter = 0;
        layout->cpuid = cpuid;
        layout->layout_blks = blks_per_layout;
        layout->layout_end = layout->layout_start + size_per_layout;
        layout->num_gaps_indram = 0;
        INIT_LIST_HEAD(&layout->gaps_list);
        mutex_init(&layout->layout_lock);
        hk_dbgv("layout[%d]: 0x%llx-0x%llx, total_blks: %llu\n", cpuid, layout->layout_start, layout->layout_end, layout->layout_blks);
    }
out:
    return ret;
}

int hk_layouts_free(struct hk_sb_info *sbi)
{
    struct hk_layout_info *layout;

    int cpuid;
    if (sbi->layouts) {
        for (cpuid = 0; cpuid < sbi->num_layout; cpuid++) {
            layout = &sbi->layouts[cpuid];
            hk_range_free_all(&layout->gaps_list);
        }
        kfree(sbi->layouts);
    }
    return 0;
}