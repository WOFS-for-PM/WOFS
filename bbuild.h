#ifndef _WOFS_BBUILD_H_
#define _WOFS_BBUILD_H_

#define BMBLK_ATTR      0
#define BMBLK_UNLINK    1
#define BMBLK_CREATE    2
#define BMBLK_DATA      3
#define BMBLK_NUM       (4)

#define BMBLK_SIZE(sbi) (sbi->pack_layout.tl_per_type_bm_reserved_blks << PAGE_SHIFT)

#define WOFS_BM_ADDR(sbi, bmblk_type) \
    (u8 *)((u64)sbi->pack_layout.bm_start + (bmblk_type * (sbi->pack_layout.tl_per_type_bm_reserved_blks << WOFS_BLK_SHIFT)))

#endif