#ifndef _WOFS_DBG_H_
#define _WOFS_DBG_H_

#include "wofs.h"

static inline void wofs_dump_inode(struct super_block *sb, struct wofs_inode *pi)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);

    wofs_info("ino: %lu\n", pi->ino);
    wofs_info("i_size: %lu\n", pi->i_size);
    wofs_info("i_flags: %u\n", pi->i_flags);
    wofs_info("i_mode: %u\n", pi->i_mode);
    wofs_info("h_addr: @0x%llx\n", pi->h_addr);
    wofs_info("tstamp: 0x%llx\n", pi->tstamp);
}

static inline void wofs_dump_mentry(struct super_block *sb, struct wofs_mentry *entry)
{
    switch (entry->type) {
    case SET_ATTR:
        wofs_info("SET_ATTR: mode %u, id: %u, gid: %u, atime: %u, mtime: %u \n ctime: %u, size: %llu, tstamp: %llu\n",
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
        wofs_info("LINK_CHANGE: links: %u, ctime: %u, tstamp: %llu\n",
                le16_to_cpu(entry->entry.linkchange.links),
                le32_to_cpu(entry->entry.linkchange.ctime),
                le64_to_cpu(entry->entry.linkchange.tstamp));
        break;
    default:
        break;
    }
}

static inline void wofs_dump_mregion(struct super_block *sb, struct wofs_mregion *rg)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    int slotid;
    if (le64_to_cpu(rg->ino) != (u64)-1) {
        for (slotid = 0; slotid < WOFS_RG_ENTY_SLOTS; slotid++) {
            if (rg->last_valid_linkchange == slotid || rg->last_valid_setattr == slotid) {
                wofs_dump_mentry(sb, &rg->entries[slotid]);
            }
        }
    }
}

static void wofs_dump_jentry(struct super_block *sb, struct wofs_jentry *je)
{
#ifndef CONFIG_FINEGRAIN_JOURNAL
    switch (je->type) {

    case J_INODE:
        wofs_info("J_INODE: ino: %llu, tstamp: %llu, i_flags: %u, i_size: %llu \n i_ctime: %u, i_mtime: %u, i_atime: %u, i_mode: %u, i_links_count: %u, i_xattr: %llu \n i_uid: %u, i_gid: %u, i_generation: %u, i_create_time: %u, rdev: %u\n",
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
        wofs_info("J_DENTRY: name_len: %u, links_count: %u, mtime: %u \n ino: %llu, tstamp: (-), name: %s\n",
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
        wofs_info("J_INODE: data @ %llx\n", le64_to_cpu(je->data));
        break;
    case J_DENTRY:
        wofs_info("J_DENTRY: data @ %llx\n", le64_to_cpu(je->data));
        break;
    }
#endif
}

static void wofs_dump_journal(struct super_block *sb, struct wofs_journal *jnl)
{
    struct wofs_jentry *je;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    u64 jcur;

    wofs_info("JOURNAL: jtype: %u, jofs_start: %llu, jofs_end: %llu, jofs_head: %llu, jofs_tail: %llu\n",
            jnl->jhdr.jtype,
            le64_to_cpu(jnl->jhdr.jofs_start),
            le64_to_cpu(jnl->jhdr.jofs_end),
            le64_to_cpu(jnl->jhdr.jofs_head),
            le64_to_cpu(jnl->jhdr.jofs_tail));

    if (jnl->jhdr.jofs_head != jnl->jhdr.jofs_tail) {
        traverse_journal_entry(sbi, jcur, jnl)
        {
            je = (struct wofs_jentry *)jcur;
            wofs_dump_jentry(sb, je);
        }
    }
}

static inline void wofs_dump_super(struct super_block *sb)
{
    struct wofs_sb_info *sbi = sb->s_fs_info;
    struct wofs_super_block *wofs_sb = sbi->wofs_sb;
    int cpuid;

    wofs_info("wofs_sb->s_sum: 0x%x\n", wofs_sb->s_sum);
    wofs_info("wofs_sb->s_magic: 0x%x\n", wofs_sb->s_magic);
    wofs_info("wofs_sb->s_padding32: 0x%x\n", wofs_sb->s_padding32);
    wofs_info("wofs_sb->s_vol_name: %s\n", wofs_sb->s_volume_name);
    wofs_info("wofs_sb->s_blocksize: 0x%x\n", wofs_sb->s_blocksize);
    wofs_info("wofs_sb->s_size: 0x%llx\n", wofs_sb->s_size);
    wofs_info("wofs_sb->s_mtime: 0x%x\n", wofs_sb->s_mtime);
    wofs_info("wofs_sb->s_wtime: 0x%x\n", wofs_sb->s_wtime);
    wofs_info("wofs_sb->s_valid_umount: 0x%x\n", wofs_sb->s_valid_umount);
    /* TODO */
    // wofs_info("wofs_sb->s_tstamp: 0x%llx\n", wofs_sb->s_tstamp);
    // for (cpuid = 0; cpuid < sbi->num_layout; cpuid++) {
    //     wofs_info("layout %d: tail: 0x%llx, valid: %llu, invalid: %llu, free: %llu, total: %llu\n",
    //             cpuid, wofs_sb->s_layout[cpuid].s_atomic_counter, wofs_sb->s_layout[cpuid].s_ind.valid_blks,
    //             wofs_sb->s_layout[cpuid].s_ind.invalid_blks, wofs_sb->s_layout[cpuid].s_ind.free_blks,
    //             wofs_sb->s_layout[cpuid].s_ind.total_blks);
    // }
}

static inline void wofs_dump_ref_data(obj_ref_data_t *ref_data)
{
    wofs_info("logical: %lu - %lu\n", ref_data->ofs >> PAGE_SHIFT, (ref_data->ofs >> PAGE_SHIFT) + ref_data->num - 1);
    wofs_info("physical: %lu - %lu\n", ref_data->data_offset >> PAGE_SHIFT, (ref_data->data_offset >> PAGE_SHIFT) + ref_data->num - 1);
}

static inline char *__wofs_get_file_type(unsigned short i_mode)
{
    switch (i_mode & S_IFMT) {
    case S_IFSOCK:
        return "s";
    case S_IFLNK:
        return "l";
    case S_IFREG:
        return "-";
    case S_IFBLK:
        return "b";
    case S_IFDIR:
        return "d";
    case S_IFCHR:
        return "c";
    case S_IFIFO:
        return "p";
    default:
        return "?";
    }
}

static inline void wofs_dump_sih(struct wofs_inode_info_header *sih)
{
    wofs_info("sih->ino: %llu\n", sih->ino);
    printk("\tsih->ino: %llu, sih->i_flags: 0x%x, sih->i_size: %llu, \n\
\tsih->i_ctime: %u, sih->i_mtime: %u, sih->i_atime: %u, \n\
\tsih->i_mode: 0x%x (%s), sih->i_links_count: %u, sih->i_uid: %u, \n\
\tsih->i_gid: %u\n",
            sih->ino,
            sih->i_flags,
            sih->i_size,
            sih->i_ctime,
            sih->i_mtime,
            sih->i_atime,
            sih->i_mode,
            __wofs_get_file_type(sih->i_mode),
            sih->i_links_count,
            sih->i_uid,
            sih->i_gid);
}

static inline void wofs_dump_inode_map(struct wofs_sb_info *sbi) {
    imap_t *imap = &sbi->pack_layout.obj_mgr->prealloc_imap;
    struct wofs_inode_info_header *sih;
    int bkt;
    
    hash_for_each(imap->map, bkt, sih, hnode) {
        wofs_dump_sih(sih);
    }
}

#endif /* _WOFS_DBG_H_ */