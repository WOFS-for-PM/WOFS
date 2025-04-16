#include "wofs.h"

int wofs_format_meta(struct super_block *sb)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    unsigned long irq_flags = 0;
    struct wofs_header *hdr;
    struct wofs_mregion *rg;
    struct wofs_journal *jnl;
    unsigned long bid, rgid, txid;

    /* Format Bitmaps for Two-Layer Allocator */
    wofs_memunlock_range(sb, (void *)sbi->pack_layout.bm_start , sbi->pack_layout.bm_size, &irq_flags);
    memset_nt_large((void *)sbi->pack_layout.bm_start , 0, sbi->pack_layout.bm_size);
    wofs_memlock_range(sb, (void *)sbi->pack_layout.bm_start , sbi->pack_layout.bm_size, &irq_flags);

    wofs_info("meta format done.\n");
    return 0;
}