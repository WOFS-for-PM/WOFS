#include "wofs.h"

int wofs_block_symlink(struct super_block *sb, struct inode *inode,
                     const char *symname, int len, void *out_blk_addr)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_inode_info *si = WOFS_I(inode);
    struct wofs_inode_info_header *sih = si->header;
    struct wofs_layout_prep prep;
    unsigned long blks = 0;
    u64 blk_addr = 0;
    u64 blk_cur;
    unsigned long irq_flags = 0;
    int ret = 0;
    obj_ref_data_t *ref = NULL;

    blk_cur = 0;
    ref = (obj_ref_data_t *)wofs_inode_get_slot(sih, 0);
    if (ref) {
        blk_addr = get_pm_addr(sbi, ref->data_offset);
    }

    if (blk_addr == 0) {
        blks = 1;
        ret = wofs_alloc_blocks(sb, &blks, true, &prep);
        if (ret) {
            wofs_dbgv("%s: alloc blocks failed\n", __func__);
            ret = -ENOSPC;
            return ret;
        }
        blk_addr = prep.target_addr;
    }

    /* the block is zeroed already */
    wofs_memunlock_block(sb, (void *)blk_addr, &irq_flags);
    memcpy_to_pmem_nocache((void *)blk_addr, symname, len);
    wofs_memlock_block(sb, (void *)blk_addr, &irq_flags);

    if (out_blk_addr) {
        *(u64 *)out_blk_addr = blk_addr;
    }

    return 0;
}

/* FIXME: Temporary workaround */
static int wofs_readlink_copy(char __user *buffer, int buflen, const char *link)
{
    int len = PTR_ERR(link);

    if (IS_ERR(link))
        goto out;

    len = strlen(link);
    if (len > (unsigned int)buflen)
        len = buflen;
    if (copy_to_user(buffer, link, len))
        len = -EFAULT;
out:
    return len;
}

static int wofs_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
    struct inode *inode = dentry->d_inode;
    struct super_block *sb = inode->i_sb;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_inode_info *si = WOFS_I(inode);
    struct wofs_inode_info_header *sih = si->header;
    u64 blk_addr;
    obj_ref_data_t *ref = NULL;

    ref = (obj_ref_data_t *)wofs_inode_get_slot(sih, 0);
    blk_addr = get_pm_addr(sbi, ref->data_offset);

    return wofs_readlink_copy(buffer, buflen, (char *)blk_addr);
}

static const char *wofs_get_link(struct dentry *dentry, struct inode *inode,
                               struct delayed_call *done)
{
    struct super_block *sb = inode->i_sb;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_inode_info *si = WOFS_I(inode);
    struct wofs_inode_info_header *sih = si->header;
    u64 blk_addr;
    obj_ref_data_t *ref = NULL;
    ref = (obj_ref_data_t *)wofs_inode_get_slot(sih, 0);

    blk_addr = get_pm_addr(sbi, ref->data_offset);

    return (char *)blk_addr;
}

const struct inode_operations wofs_symlink_inode_operations = {
    .readlink = wofs_readlink,
    .get_link = wofs_get_link,
    .setattr = wofs_notify_change,
};
