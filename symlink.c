#include "hunter.h"

int hk_block_symlink(struct super_block *sb, struct hk_inode *pi,
					 struct inode *inode, const char *symname, int len,
					 void *out_blk_addr)
{
	struct hk_sb_info 	 *sbi = HK_SB(sb);
	struct hk_inode_info *si = HK_I(inode);
	struct hk_inode_info_header *sih = &si->header;
	struct hk_layout_preps	preps;
	struct hk_layout_prep	*prep = NULL;
	struct hk_layout_prep	tmp_prep;
	u64						blk_addr = 0;
	u64						blk_cur;
	unsigned long irq_flags = 0;
	
	blk_cur = 0;
	blk_addr = TRANS_OFS_TO_ADDR(sbi, linix_get(&sih->ix, blk_cur));
	
	if (blk_addr == 0) {
		hk_prepare_layouts(sb, 1, true, &preps);
		hk_trv_prepared_layouts_init(&preps);
		prep = hk_trv_prepared_layouts(sb, &preps);
		if (!prep) {
			hk_dbg("%s: ERROR: No prep found for index\n", __func__);
			hk_prepare_gap(sb, false, &tmp_prep);
			if (tmp_prep.target_addr == 0) {
				hk_dbgv("%s: prepare layout failed\n", __func__);
				BUG_ON(1);
				return -ENOSPC;	
			}
			blk_addr = tmp_prep.target_addr;
		}
		else {
			blk_addr = prep->target_addr;
		}
	}

	
	/* the block is zeroed already */
	hk_memunlock_block(sb, (void *)blk_addr, &irq_flags);
	memcpy_to_pmem_nocache((void *)blk_addr, symname, len);
	hk_memlock_block(sb, (void *)blk_addr, &irq_flags);

	use_layout_for_addr(sb, blk_addr);
	sm_valid_hdr(sb, blk_addr, inode->i_ino, blk_cur, get_version(sbi));
	unuse_layout_for_addr(sb, blk_addr);
	
	/* first block */
	linix_insert(&sih->ix, blk_cur, blk_addr, true);
	
	if (out_blk_addr) {
		*(u64 *)out_blk_addr = blk_addr;
	}

#ifndef CONFIG_FINEGRAIN_JOURNAL
	/* use size change for new inode creation */
	hk_commit_sizechange(sb, inode, len);
#endif

	return 0;
}

/* FIXME: Temporary workaround */
static int hk_readlink_copy(char __user *buffer, int buflen, const char *link)
{
	int len = PTR_ERR(link);

	if (IS_ERR(link))
		goto out;

	len = strlen(link);
	if (len > (unsigned int) buflen)
		len = buflen;
	if (copy_to_user(buffer, link, len))
		len = -EFAULT;
out:
	return len;
}

static int hk_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct hk_sb_info  *sbi = HK_SB(sb);
	struct hk_inode_info *si = HK_I(inode);
	struct hk_inode_info_header *sih = &si->header;
	u64 blk_addr;

	blk_addr = TRANS_OFS_TO_ADDR(sbi, linix_get(&sih->ix, 0));

	return hk_readlink_copy(buffer, buflen, (char *)blk_addr);
}

static const char *hk_get_link(struct dentry *dentry, struct inode *inode,
	struct delayed_call *done)
{
	struct super_block *sb = inode->i_sb;
	struct hk_sb_info  *sbi = HK_SB(sb);
	struct hk_inode_info *si = HK_I(inode);
	struct hk_inode_info_header *sih = &si->header;
	u64 blk_addr;

	blk_addr = TRANS_OFS_TO_ADDR(sbi, linix_get(&sih->ix, 0));

	return (char *)blk_addr;
}

const struct inode_operations hk_symlink_inode_operations = {
	.readlink	= hk_readlink,
	.get_link	= hk_get_link,
	.setattr	= hk_notify_change,
};
