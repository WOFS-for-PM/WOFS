#ifndef _HK_DBG_H_
#define _HK_DBG_H_

#include "hunter.h"

static inline void hk_dump_inode(struct super_block *sb, struct hk_inode *pi)
{
    struct hk_sb_info *sbi = HK_SB(sb);

    hk_info("ino: %lu\n", pi->ino);
    hk_info("i_size: %lu\n", pi->i_size);
    hk_info("i_flags: %u\n", pi->i_flags);
    hk_info("i_mode: %u\n", pi->i_mode);
    hk_info("h_addr: @0x%llx\n", pi->h_addr);
    hk_info("tstamp: 0x%llx\n", pi->tstamp);
}

static inline void hk_dump_layout_info(struct hk_layout_info *layout)
{
    struct hk_indicator *ind = &layout->ind;
    hk_info("layout: %d===>\n", layout->cpuid);
    hk_info("-----------------------------------\n");
    hk_info("tail: 0x%llx\n", layout->atomic_counter);
    hk_info("valid_blks: %llu, invalid_blks: %llu, free_blks: %llu, prep_blks: %llu, total: %llu\n",
            ind->valid_blks, ind->invalid_blks, ind->free_blks, ind->prep_blks, ind->total_blks);
}

static inline void hk_dump_mentry(struct super_block *sb, struct hk_mentry *entry)
{
    switch (entry->type) {
    case SET_ATTR:
        hk_info("SET_ATTR: mode %u, id: %u, gid: %u, atime: %u, mtime: %u \n ctime: %u, size: %llu, tstamp: %llu\n",
                le32_to_cpu(entry->entry.setattr.mode),
                le32_to_cpu(entry->entry.setattr.uid),
                le32_to_cpu(entry->entry.setattr.gid),
                le32_to_cpu(entry->entry.setattr.atime),
                le32_to_cpu(entry->entry.setattr.mtime),
                le32_to_cpu(entry->entry.setattr.ctime),
                le64_to_cpu(entry->entry.setattr.size),
                le64_to_cpu(entry->entry.setattr.tstamp));
        break;
    case LINK_CHANGE:
        hk_info("LINK_CHANGE: links: %u, ctime: %u, tstamp: %llu\n",
                le16_to_cpu(entry->entry.linkchange.links),
                le32_to_cpu(entry->entry.linkchange.ctime),
                le64_to_cpu(entry->entry.linkchange.tstamp));
        break;
    default:
        break;
    }
}

static inline void hk_dump_mregion(struct super_block *sb, struct hk_mregion *rg)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    int slotid;
    if (le64_to_cpu(rg->ino) != (u64)-1) {
        for (slotid = 0; slotid < HK_RG_ENTY_SLOTS; slotid++) {
            if (rg->last_valid_linkchange == slotid || rg->last_valid_setattr == slotid) {
                hk_dump_mentry(sb, &rg->entries[slotid]);
            }
        }
    }
}


static void hk_dump_jentry(struct super_block *sb, struct hk_jentry *je)
{
#ifndef CONFIG_FINEGRAIN_JOURNAL
    switch (je->type) {

    case J_INODE:
        hk_info("J_INODE: ino: %llu, tstamp: %llu, i_flags: %u, i_size: %llu \n i_ctime: %u, i_mtime: %u, i_atime: %u, i_mode: %u, i_links_count: %u, i_xattr: %llu \n i_uid: %u, i_gid: %u, i_generation: %u, i_create_time: %u, rdev: %u\n",
                le64_to_cpu(je->jinode.ino),
                le64_to_cpu(je->jinode.tstamp),
                le32_to_cpu(je->jinode.i_flags),
                le64_to_cpu(je->jinode.i_size),
                le32_to_cpu(je->jinode.i_ctime),
                le32_to_cpu(je->jinode.i_mtime),
                le32_to_cpu(je->jinode.i_atime),
                le16_to_cpu(je->jinode.i_mode),
                le16_to_cpu(je->jinode.i_links_count),
                le64_to_cpu(je->jinode.i_xattr),
                le32_to_cpu(je->jinode.i_uid),
                le32_to_cpu(je->jinode.i_gid),
                le32_to_cpu(je->jinode.i_generation),
                le32_to_cpu(je->jinode.i_create_time),
                le32_to_cpu(je->jinode.dev.rdev));
        break;
    case J_DENTRY:
        hk_info("J_DENTRY: name_len: %u, links_count: %u, mtime: %u \n ino: %llu, tstamp: (-), name: %s\n",
                je->jdentry.name_len,
                le16_to_cpu(je->jdentry.links_count),
                le32_to_cpu(je->jdentry.mtime),
                le64_to_cpu(je->jdentry.ino),
                je->jdentry.name);
        break;
    }
#else
    switch (je->type) {
    case J_INODE:
        hk_info("J_INODE: data @ %llx\n", le64_to_cpu(je->data));
        break;
    case J_DENTRY:
        hk_info("J_DENTRY: data @ %llx\n", le64_to_cpu(je->data));
        break;
    }
#endif
}

static void hk_dump_journal(struct super_block *sb, struct hk_journal *jnl)
{
    struct hk_jentry *je;
    struct hk_sb_info *sbi = HK_SB(sb);
    u64 jcur;

    hk_info("JOURNAL: jtype: %u, jofs_start: %llu, jofs_end: %llu, jofs_head: %llu, jofs_tail: %llu\n",
            jnl->jhdr.jtype,
            le64_to_cpu(jnl->jhdr.jofs_start),
            le64_to_cpu(jnl->jhdr.jofs_end),
            le64_to_cpu(jnl->jhdr.jofs_head),
            le64_to_cpu(jnl->jhdr.jofs_tail));

    if (jnl->jhdr.jofs_head != jnl->jhdr.jofs_tail) {
        traverse_journal_entry(sbi, jcur, jnl)
        {
            je = (struct hk_jentry *)jcur;
            hk_dump_jentry(sb, je);
        }
    }
}


static inline void hk_dump_super(struct super_block *sb)
{
    struct hk_sb_info *sbi = sb->s_fs_info;
    struct hk_super_block *hk_sb = sbi->hk_sb;
    int cpuid;

    hk_info("hk_sb->s_sum: 0x%x\n", hk_sb->s_sum);
    hk_info("hk_sb->s_magic: 0x%x\n", hk_sb->s_magic);
    hk_info("hk_sb->s_padding32: 0x%x\n", hk_sb->s_padding32);
    hk_info("hk_sb->s_vol_name: %s\n", hk_sb->s_volume_name);
    hk_info("hk_sb->s_blocksize: 0x%x\n", hk_sb->s_blocksize);
    hk_info("hk_sb->s_size: 0x%llx\n", hk_sb->s_size);
    hk_info("hk_sb->s_mtime: 0x%x\n", hk_sb->s_mtime);
    hk_info("hk_sb->s_wtime: 0x%x\n", hk_sb->s_wtime);
    hk_info("hk_sb->s_valid_umount: 0x%x\n", hk_sb->s_valid_umount);
    /* TODO */
    // hk_info("hk_sb->s_tstamp: 0x%llx\n", hk_sb->s_tstamp);
    // for (cpuid = 0; cpuid < sbi->num_layout; cpuid++) {
    //     hk_info("layout %d: tail: 0x%llx, valid: %llu, invalid: %llu, free: %llu, total: %llu\n",
    //             cpuid, hk_sb->s_layout[cpuid].s_atomic_counter, hk_sb->s_layout[cpuid].s_ind.valid_blks,
    //             hk_sb->s_layout[cpuid].s_ind.invalid_blks, hk_sb->s_layout[cpuid].s_ind.free_blks,
    //             hk_sb->s_layout[cpuid].s_ind.total_blks);
    // }
}

static inline void hk_dump_ref_data(obj_ref_data_t *ref_data)
{
    hk_info("logical: %lu - %lu\n", ref_data->ofs >> PAGE_SHIFT, (ref_data->ofs >> PAGE_SHIFT) + ref_data->num - 1);
    hk_info("physical: %lu - %lu\n", ref_data->data_offset >> PAGE_SHIFT, (ref_data->data_offset >> PAGE_SHIFT) + ref_data->num - 1);
}

#endif /* _HK_DBG_H_ */