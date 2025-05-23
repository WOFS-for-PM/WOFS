#ifndef _HK_META_H
#define _HK_META_H

#include "hunter.h"

#define HDR_INVALID 0
#define HDR_VALID 1
#define HDR_PENDING 2

struct hk_header {
    u8 valid;        //! GC flag, 8B atomic persistence
    u64 ino;         //! Indicate which inode it belongs to
    u64 tstamp;      //! Version control
    u64 f_blk;       //! Indicate which blk it resides in
    u64 ofs_next;    //! Next addr relative to NVM start
    u64 ofs_prev;    //! Prev addr relative to NVM start
    u8 paddings[11]; //! Padding to make it 64B
};

struct hk_setattr_entry {
    __le16 mode;
    __le32 uid;
    __le32 gid;
    __le32 atime;
    __le32 mtime;
    __le32 ctime;
    __le64 size; /* File size after truncation */
    __le64 tstamp;
};

struct hk_linkchange_entry {
    __le16 links;
    __le32 ctime;
    __le64 tstamp;
};

enum hk_entry_type {
    SET_ATTR,
    LINK_CHANGE,
};

struct hk_mentry {
    u8 type;
    union {
        struct hk_setattr_entry setattr;
        struct hk_linkchange_entry linkchange;
    } entry;
};

struct hk_mregion {
    u8 applying;
    u8 last_valid_setattr;
    u8 last_valid_linkchange;
    __le64 ino;
    struct hk_mentry entries[HK_RG_ENTY_SLOTS];
} __attribute((__packed__));

struct hk_jdentry {
    u8 name_len; /* length of the dentry name */
    __le16 links_count;
    __le32 mtime; /* For both mtime and ctime */
    __le64 ino;   /* inode no pointed to by this entry */
    __le64 tstamp;
    u8 name[HK_NAME_LEN + 1]; /* File name */
} __attribute((__packed__));

struct hk_jinode {
    __le32 i_flags;       /* Inode flags */
    __le64 i_size;        /* Size of data in bytes */
    __le32 i_ctime;       /* Inode modification time */
    __le32 i_mtime;       /* Inode Linear Index Modification time */
    __le32 i_atime;       /* Access time */
    __le16 i_mode;        /* File mode */
    __le16 i_links_count; /* Links count */

    __le64 i_xattr; /* Extended attribute block */

    __le32 i_uid;         /* Owner Uid */
    __le32 i_gid;         /* Group Id */
    __le32 i_generation;  /* File version (for NFS) */
    __le32 i_create_time; /* Create time */
    __le64 ino;           /* hk inode number */

    __le64 h_addr; /* Inode as the head of the files */
    __le64 tstamp; /* Time stamp */

    struct {
        __le32 rdev; /* major/minor # */
    } dev;           /* device inode */
} __attribute((__packed__));

enum hk_jentry_type {
    J_INODE,
    J_DENTRY,
};

struct hk_jentry {
    u8 type;
#ifndef CONFIG_FINEGRAIN_JOURNAL
    union {
        struct hk_jdentry jdentry;
        struct hk_jinode jinode;
    };
#else
    __le64 data;
#endif
} __attribute((__packed__));

enum hk_journal_type {
    IDLE,
    CREATE,
    MKDIR,
    LINK,
    SYMLINK,
    UNLINK,
    RENAME
};

struct hk_jheader {
    u8 jtype;
    __le64 jofs_start; /* Start addr relative to NVM start */
    __le64 jofs_end;
    __le64 jofs_head; /* Head Addr relative to NVM start  */
    __le64 jofs_tail;
} __attribute((__packed__));

struct hk_jbody {
    u8 jbody[HK_JOURNAL_SIZE - sizeof(struct hk_jheader)];
} __attribute((__packed__));

struct hk_journal {
    struct hk_jheader jhdr;
    struct hk_jbody jbody;
} __attribute((__packed__));

#define HK_MAX_OBJ_INVOVED 5
struct hk_jentry_info {
    u8 valid;
    struct hk_jentry jentry;
};

struct hk_tx_info {
    enum hk_journal_type jtype;
    struct hk_jentry_info ji_pi;
    struct hk_jentry_info ji_pd;
    struct hk_jentry_info ji_pd_new;
    struct hk_jentry_info ji_pi_par;
    struct hk_jentry_info ji_pi_new;
};

#define traverse_inode_hdr(sbi, pi, hdr_traverse) for (hdr_traverse = TRANS_OFS_TO_ADDR(sbi, le64_to_cpu(pi->h_addr)); hdr_traverse != NULL; hdr_traverse = hdr_traverse == NULL ? NULL : TRANS_OFS_TO_ADDR(sbi, (((struct hk_header *)hdr_traverse)->ofs_next)))

#define traverse_tx_info(ji, slotid, info) for (ji = &info->ji_pi, slotid = 0; slotid < HK_MAX_OBJ_INVOVED; slotid++, ji = hk_tx_get_ji_from_tx_info(info, slotid))

#define traverse_journal_entry(sbi, jcur, jnl) for (jcur = TRANS_OFS_TO_ADDR(sbi, jnl->jhdr.jofs_head); jcur != TRANS_OFS_TO_ADDR(sbi, jnl->jhdr.jofs_tail); jcur = jcur + sizeof(struct hk_jentry) > TRANS_OFS_TO_ADDR(sbi, jnl->jhdr.jofs_end) ? TRANS_OFS_TO_ADDR(sbi, jnl->jhdr.jofs_start) + sizeof(struct hk_jentry) : jcur + sizeof(struct hk_jentry))

#endif /* _HK_META_H */