#ifndef _HK_INODE_H
#define _HK_INODE_H

#include "hunter.h"

struct hk_inode;
struct hk_inode_info_header;

enum hk_new_inode_type {
    TYPE_CREATE = 0,
    TYPE_MKNOD,
    TYPE_SYMLINK,
    TYPE_MKDIR
};

/*
 * Structure of an inode in PMEM
 */
struct hk_inode {
    u8 valid;             /* Is this inode valid? */
    __le32 i_flags;       /* Inode flags */
    __le64 i_size;        /* Size of data in bytes */
    __le32 i_ctime;       /* Inode modification time */
    __le32 i_mtime;       /* Inode Linear Index Modification time */
    __le32 i_atime;       /* Access time */
    __le16 i_mode;        /* File mode */
    __le16 i_links_count; /* Links count */

    __le64 i_xattr; /* Extended attribute block */

    /* second 40 bytes */
    __le32 i_uid;         /* Owner Uid */
    __le32 i_gid;         /* Group Id */
    __le32 i_generation;  /* File version (for NFS) */
    __le32 i_create_time; /* Create time */
    __le64 ino;           /* hk inode number */
    __le64 tstamp;        /* Time stamp */
    __le64 h_addr;        /* Inode as the head of the files */

    struct {
        __le32 rdev; /* major/minor # */
    } dev;           /* device inode */

    //! We don't need this for now
    __le32 csum; /* CRC32 checksum */

    u8 paddings[PM_ACCESS_GRANU - 93];
} __attribute((__packed__));

static_assert(sizeof(struct hk_inode) != PM_ACCESS_GRANU, "hk_inode size mismatch");

struct latest_fop_objs {
    obj_ref_inode_t *latest_inode;
    obj_ref_attr_t *latest_attr;
    u64 latest_inline_attr;
};

/*
 * hk-specific inode state kept in DRAM
 */
struct hk_inode_info_header {
    struct hlist_node hnode;
    struct hk_inode_info *si;
    u32 ino;
    struct linix ix;                        /* Linear Index for blks in use */
    DECLARE_HASHTABLE(dirs, HK_HASH_BITS7); /* Hash table for dirs */
    u64 i_num_dentrys;                      /* Dentrys tail */
    struct rb_root vma_tree;                /* Write vmas */
    struct list_head list;                  /* SB list of mmap sih */
    int num_vmas;
    unsigned short i_mode; /* Dir or file? */
    off_t last_end;
    unsigned int i_flags;
    unsigned long i_size;
    unsigned long i_blocks;
    u32 i_ctime;
    u32 i_mtime;
    u32 i_atime;  /* Access time */
    u32 i_uid;    /* Owner Uid */
    u32 i_gid;    /* Group Id */
    u16 i_links_count;

    union {
        /* for lfs or local */
        struct {
            u64 pi_addr;          /* Exact hk_inode addr */
            u64 last_link_change; /* Last link change entry */
            u64 last_dentry;      /* Last updated dentry */
            u64 tstamp;           /* Time stamp for Version Control */
            u64 h_addr;           /* First blk logic offset */
        } norm_spec;
        /* for pack (write-once) */
        struct {
            struct latest_fop_objs latest_fop;
        } pack_spec;
    };
};

/*
 * DRAM state for inodes
 */
struct hk_inode_info {
    struct hk_inode_info_header *header;
    struct inode vfs_inode;
    int layout_type;
};

static inline struct hk_inode_info *HK_I(struct inode *inode)
{
    return container_of(inode, struct hk_inode_info, vfs_inode);
}

static inline struct hk_inode_info_header *HK_IH(struct inode *inode)
{
    struct hk_inode_info *si = HK_I(inode);
    return si->header;
}

/* If this is part of a read-modify-write of the inode metadata,
 * hk_memunlock_inode() before calling!
 */
static inline struct hk_inode *hk_get_inode_by_ino(struct super_block *sb, u64 ino)
{
    struct hk_sb_info *sbi = HK_SB(sb);

    if (ino >= HK_NUM_INO)
        return NULL;

    return (struct hk_inode *)(sbi->norm_layout.ino_tab_addr + ino * sizeof(struct hk_inode));
}

static inline struct hk_inode *hk_get_inode(struct super_block *sb,
                                            struct inode *inode)
{
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    struct hk_inode fake_pi;
    void *addr;
    int rc;

    addr = sih->norm_spec.pi_addr;
    rc = memcpy_mcsafe(&fake_pi, addr, sizeof(struct hk_inode));
    if (rc)
        return NULL;

    return (struct hk_inode *)addr;
}

typedef struct inode_mgr {
    struct hk_sb_info *sbi; /* the superblock */
#ifndef CONFIG_PERCORE_IALLOCATOR
    spinlock_t ilist_lock;
    struct list_head ilist; /* Sort asending */
#else
    spinlock_t *ilist_locks;
    struct list_head *ilists;
    bool *ilist_init;
#endif
} inode_mgr_t;

#endif
