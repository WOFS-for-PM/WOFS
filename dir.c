#include "hunter.h"

#define DT2IF(dt)  (((dt) << 12) & S_IFMT)
#define IF2DT(sif) (((sif)&S_IFMT) >> 12)

static int hk_readdir(struct file *file, struct dir_context *ctx)
{
    struct inode *inode = file_inode(file);
    struct super_block *sb = inode->i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *psih = si->header;
    unsigned long pos = 0;
    unsigned bkt;
    int ret;

    INIT_TIMING(readdir_time);

    HK_START_TIMING(readdir_t, readdir_time);
    pos = ctx->pos;

    if (pos == READDIR_END)
        goto out;

    /* Commit dots */
    if (!dir_emit_dots(file, ctx))
        return 0;

    if (ENABLE_META_PACK(sb)) {
        obj_ref_dentry_t *ref_dentry;
        struct hk_obj_dentry *obj_dentry;
        struct hk_inode_info_header *sih;

        hash_for_each(psih->dirs, bkt, ref_dentry, hnode)
        {
            obj_dentry = (struct hk_obj_dentry *)get_pm_addr(sbi, ref_dentry->hdr.addr);
            sih = obj_mgr_get_imap_inode(sbi->pack_layout.obj_mgr, ref_dentry->target_ino);
            if (!dir_emit(ctx, obj_dentry->name, strlen(obj_dentry->name),
                          sih->ino,
                          IF2DT(sih->i_mode))) {
                hk_dbg("%s: dir_emit failed\n", __func__);
                return -EIO;
            }
        }

    } else {
        struct hk_inode *pidir;
        struct hk_inode *child_pi;
        struct hk_dentry_info *cur;
        u64 pi_addr;

        pidir = hk_get_inode(sb, inode);
        hk_dbgv("%s: ino %llu, size %llu, pos 0x%llx\n",
                __func__, (u64)inode->i_ino,
                pidir->i_size, ctx->pos);

        hash_for_each(psih->dirs, bkt, cur, node)
        {
            child_pi = hk_get_inode_by_ino(sb, cur->direntry->ino);
            if (!dir_emit(ctx, cur->direntry->name, cur->direntry->name_len,
                          cur->direntry->ino,
                          IF2DT(le16_to_cpu(child_pi->i_mode)))) {
                hk_dbg("%s: dir_emit failed\n", __func__);
                return -EIO;
            }
        }
    }

    ctx->pos = READDIR_END;

out:
    HK_END_TIMING(readdir_t, readdir_time);
    hk_dbgv("%s return\n", __func__);
    return 0;
}

const struct file_operations hk_dir_operations = {
    .llseek = generic_file_llseek,
    .read = generic_read_dir,
    .iterate = hk_readdir,
    .fsync = noop_fsync,
    .unlocked_ioctl = hk_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = hk_compat_ioctl,
#endif
};
