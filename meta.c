#include "wofs.h"

/* ======================= ANCHOR: Summary Header ========================= */

/* start of pblk */
u64 sm_get_addr_by_hdr(struct super_block *sb, u64 hdr)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    if (ENABLE_META_LOCAL(sb)) {
        u64 blk = (hdr - sbi->norm_layout.sm_addr) / sizeof(struct wofs_header);
        return sbi->d_addr + (blk * WOFS_PBLK_SZ(sbi));
    } else {
        return hdr + sizeof(struct wofs_header) - WOFS_PBLK_SZ(sbi);
    }
}

struct wofs_header *sm_get_hdr_by_blk(struct super_block *sb, u64 blk)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    if (ENABLE_META_LOCAL(sb)) {
        return (struct wofs_header *)(sbi->norm_layout.sm_addr + blk * sizeof(struct wofs_header));
    } else {
        return (struct wofs_header *)(sbi->d_addr + (blk + 1) * WOFS_PBLK_SZ(sbi) - sizeof(struct wofs_header));
    }
}

struct wofs_header *sm_get_hdr_by_addr(struct super_block *sb, u64 addr)
{
    u64 blk;
    struct wofs_sb_info *sbi = WOFS_SB(sb);

    if (addr < sbi->d_addr) {
        wofs_info("%s: Invalid Addr\n", __func__);
        BUG_ON(1);
    }

    blk = (addr - sbi->d_addr) / WOFS_PBLK_SZ(sbi);

    wofs_dbgv("sbi->norm_layout.sm_addr: %llx, %d, %d\n", sbi->norm_layout.sm_addr, sizeof(struct wofs_header), blk * sizeof(struct wofs_header));

    return sm_get_hdr_by_blk(sb, blk);
}

struct wofs_layout_info *sm_get_layout_by_hdr(struct super_block *sb, u64 hdr)
{
    int cpuid;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    u64 addr = sm_get_addr_by_hdr(sb, hdr);
    u64 size_per_layout = _round_down(sbi->d_size / sbi->num_layout, WOFS_PBLK_SZ(sbi));

    cpuid = (addr - sbi->d_addr) / size_per_layout;

    /* cpuid could larger that (sbi->num_layout - 1) */
    cpuid = cpuid >= sbi->num_layout ? cpuid - 1 : cpuid;

    return &sbi->layouts[cpuid];
}

/* TODO: Not protect hdr in remove function */
int sm_remove_hdr(struct super_block *sb, struct wofs_inode *pi, struct wofs_header *hdr)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    bool is_hdr_unlock_already = false;
    unsigned long irq_flags = 0;

    if (TRANS_OFS_TO_ADDR(sbi, hdr->ofs_prev) == pi) {
        wofs_memunlock_inode(sb, pi, &irq_flags);
        pi->h_addr = hdr->ofs_next;
        wofs_memlock_inode(sb, pi, &irq_flags);
    } else {
        wofs_memunlock_hdr(sb, hdr, &irq_flags);
        ((struct wofs_header *)TRANS_OFS_TO_ADDR(sbi, hdr->ofs_prev))->ofs_next = hdr->ofs_next;
        is_hdr_unlock_already = true;
    }

    if (!is_hdr_unlock_already) {
        wofs_memunlock_hdr(sb, hdr, &irq_flags);
    }

    if (TRANS_OFS_TO_ADDR(sbi, hdr->ofs_next) != NULL) {
        ((struct wofs_header *)TRANS_OFS_TO_ADDR(sbi, hdr->ofs_next))->ofs_prev = hdr->ofs_prev;
    }
    hdr->ofs_next = NULL;
    hdr->ofs_prev = NULL;
    wofs_memlock_hdr(sb, hdr, &irq_flags);

    return 0;
}

int sm_insert_hdr(struct super_block *sb, struct wofs_inode *pi, struct wofs_header *hdr)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    unsigned long irq_flags = 0;

    /* Write Hdr, then persist it */
    wofs_memunlock_hdr(sb, hdr, &irq_flags);
    /* Change the link */
    hdr->ofs_prev = TRANS_ADDR_TO_OFS(sbi, pi);
    hdr->ofs_next = pi->h_addr;
    wofs_memunlock_inode(sb, pi, &irq_flags);
    if (pi->h_addr != NULL) {
        ((struct wofs_header *)TRANS_OFS_TO_ADDR(sbi, pi->h_addr))->ofs_prev = TRANS_ADDR_TO_OFS(sbi, hdr);
    }
    pi->h_addr = TRANS_ADDR_TO_OFS(sbi, hdr);
    wofs_memlock_inode(sb, pi, &irq_flags);
    wofs_memlock_hdr(sb, hdr, &irq_flags);
    return 0;
}

int sm_invalid_hdr(struct super_block *sb, u64 blk_addr, u64 ino)
{
    /*! Note: Do not update tstamp in invalid process, since version control */
    struct wofs_inode *pi;
    struct inode *inode;
    struct wofs_header *hdr;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    unsigned long irq_flags = 0;
    INIT_TIMING(invalid_time);

    WOFS_START_TIMING(sm_invalid_t, invalid_time);
    pi = wofs_get_inode_by_ino(sb, ino);
    hdr = sm_get_hdr_by_addr(sb, blk_addr);
    sm_remove_hdr(sb, pi, hdr);

    wofs_memunlock_hdr(sb, hdr, &irq_flags);
    wofs_flush_buffer(hdr, sizeof(struct wofs_header), true);
    hdr->valid = 0;
    wofs_flush_buffer(hdr, sizeof(struct wofs_header), true);
    wofs_memlock_hdr(sb, hdr, &irq_flags);

    WOFS_END_TIMING(sm_invalid_t, invalid_time);
    return 0;
}

int sm_valid_hdr(struct super_block *sb, u64 blk_addr, u64 ino, u64 f_blk, u64 tstamp)
{
    struct wofs_inode *pi;
    struct wofs_header *hdr;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct inode *inode = NULL;
    u64 blk;
    unsigned long irq_flags = 0;
    INIT_TIMING(valid_time);

    WOFS_START_TIMING(sm_valid_t, valid_time);
    pi = wofs_get_inode_by_ino(sb, ino);
    if (!pi)
        return -1;

    hdr = sm_get_hdr_by_addr(sb, blk_addr);

    if (hdr->f_blk == f_blk &&
        hdr->ino == ino &&
        hdr->valid == 1) /*! No need to update */
    {
        wofs_warn("hdr@0x%llx does not need to update\n", (u64)hdr);
        return 0;
    }

    /* Change the link */
    sm_insert_hdr(sb, pi, hdr);

    /* Write Hdr, then persist it */
    wofs_memunlock_hdr(sb, hdr, &irq_flags);
    hdr->ino = ino;
    hdr->tstamp = tstamp;
    hdr->f_blk = f_blk;
    /* flush and fence here significantly hinder the performance */
    /* So that try killing it, fence once or delaying fence */
    /* wofs_flush_buffer(hdr, sizeof(struct wofs_header), true); */
    hdr->valid = 1;
    wofs_flush_buffer(hdr, sizeof(struct wofs_header), true);
    wofs_memlock_hdr(sb, hdr, &irq_flags);

    WOFS_END_TIMING(sm_valid_t, valid_time);
    return 0;
}

/* ======================= ANCHOR: Meta Regions ========================= */

struct wofs_mregion *wofs_get_region_by_rgid(struct super_block *sb, int rgid)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    return (struct wofs_mregion *)(sbi->norm_layout.rg_addr + rgid * sizeof(struct wofs_mregion));
}

struct wofs_mregion *wofs_get_region_by_ino(struct super_block *sb, u64 ino)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    int rgid;

    rgid = ino % sbi->norm_layout.rg_slots;

    return wofs_get_region_by_rgid(sb, rgid);
}

/* Make sure region is memunlocked */
int wofs_reinit_region(struct super_block *sb, struct wofs_mregion *rg)
{
    rg->ino = cpu_to_le64((u64)-1);
    rg->last_valid_setattr = cpu_to_le64((u8)-1);
    rg->last_valid_linkchange = cpu_to_le64((u8)-1);
    return 0;
}

/* pi should be unlocked */
void wofs_apply_entry(struct super_block *sb, struct wofs_inode *pi, struct wofs_mentry *entry)
{
    switch (entry->type) {
    case SET_ATTR:
        pi->i_atime = pi->i_atime >= entry->entry.setattr.atime ? pi->i_atime : entry->entry.setattr.atime;
        pi->i_ctime = pi->i_ctime >= entry->entry.setattr.ctime ? pi->i_ctime : entry->entry.setattr.ctime;
        pi->i_mtime = pi->i_mtime >= entry->entry.setattr.mtime ? pi->i_mtime : entry->entry.setattr.mtime;
        pi->i_gid = entry->entry.setattr.gid;
        pi->i_uid = entry->entry.setattr.uid;
        pi->i_size = entry->entry.setattr.size;
        pi->i_mode = entry->entry.setattr.mode;
        pi->tstamp = pi->tstamp >= entry->entry.setattr.tstamp ? pi->tstamp : entry->entry.setattr.tstamp;
        break;
    case LINK_CHANGE:
        pi->i_links_count = entry->entry.linkchange.links;
        pi->i_ctime = pi->i_ctime >= entry->entry.linkchange.ctime ? pi->i_ctime : entry->entry.linkchange.ctime;
        pi->tstamp = pi->tstamp >= entry->entry.linkchange.tstamp ? pi->tstamp : entry->entry.linkchange.tstamp;
        break;
    default:
        break;
    }
}

/* no need to handle memlock or unlock */
void wofs_apply_entry_once(struct super_block *sb, struct wofs_inode *pi, struct wofs_mentry *entry)
{
    struct wofs_mregion *rg;
    unsigned long irq_flags = 0;

    wofs_memunlock_inode(sb, pi, &irq_flags);
    wofs_apply_entry(sb, pi, entry);
    wofs_memlock_inode(sb, pi, &irq_flags);

    rg = wofs_get_region_by_ino(sb, le64_to_cpu(pi->ino));

    wofs_memunlock_mregion(sb, rg, &irq_flags);
    switch (entry->type) {
    case SET_ATTR:
        rg->last_valid_setattr = (u8)-1;
        break;
    case LINK_CHANGE:
        rg->last_valid_linkchange = (u8)-1;
        break;
    default:
        break;
    }
    wofs_memlock_mregion(sb, rg, &irq_flags);
}

int wofs_applying_region(struct super_block *sb, struct wofs_mregion *rg)
{
    u32 ino = rg->ino;
    int slotid;
    struct wofs_inode *pi = wofs_get_inode_by_ino(sb, ino);
    unsigned long irq_flags = 0;

    if (!pi->valid) {
        return -1;
    }

    wofs_memunlock_mregion(sb, rg, &irq_flags);
    rg->applying = 1;
    wofs_memlock_mregion(sb, rg, &irq_flags);
    wofs_flush_buffer(rg, sizeof(struct wofs_mregion), true);

    wofs_memunlock_inode(sb, pi, &irq_flags);
    for (slotid = 0; slotid < WOFS_RG_ENTY_SLOTS; slotid++) {
        if (rg->last_valid_setattr == slotid || rg->last_valid_linkchange == slotid) {
            wofs_apply_entry(sb, pi, &rg->entries[slotid]);
        }
    }
    wofs_memlock_inode(sb, pi, &irq_flags);
    wofs_flush_buffer(pi, sizeof(struct wofs_inode), true);

    wofs_memunlock_mregion(sb, rg, &irq_flags);
    rg->applying = 0;
    wofs_memlock_mregion(sb, rg, &irq_flags);
    wofs_flush_buffer(rg, sizeof(struct wofs_mregion), true);

    /* Invalidate the region */
    wofs_reinit_region(sb, rg);

    return 0;
}

/* apply region to pi */
int wofs_applying_region_to_inode(struct super_block *sb, struct wofs_inode *pi)
{
    struct wofs_mentry entry;
    bool commit_found = false;

    commit_found = wofs_get_cur_commit(sb, pi, SET_ATTR, &entry);
    if (commit_found) {
        wofs_apply_entry_once(sb, pi, &entry);
    }

    commit_found = wofs_get_cur_commit(sb, pi, LINK_CHANGE, &entry);
    if (commit_found) {
        wofs_apply_entry_once(sb, pi, &entry);
    }

    return 0;
}

int wofs_do_commit_inode(struct super_block *sb, u64 ino, struct wofs_mentry *entry)
{
    struct wofs_mregion *rg;
    unsigned long irq_flags = 0;
    int slotid;

    rg = wofs_get_region_by_ino(sb, ino);
    /* Evict Region */
    if (rg->ino != ino && rg->ino != (u64)-1) {
        wofs_applying_region(sb, rg);
    }

    wofs_memunlock_mregion(sb, rg, &irq_flags);
    rg->ino = ino;

    for (slotid = 0; slotid < WOFS_RG_ENTY_SLOTS; slotid++) {
        if (slotid != rg->last_valid_linkchange && slotid != rg->last_valid_setattr) {
            memcpy_to_pmem_nocache(&rg->entries[slotid], entry, sizeof(struct wofs_mentry));

            /* Commit The Write */
            switch (entry->type) {
            case SET_ATTR:
                rg->last_valid_setattr = slotid;
                break;
            case LINK_CHANGE:
                rg->last_valid_linkchange = slotid;
                break;
            default:
                break;
            }

            wofs_flush_buffer(rg, sizeof(struct wofs_mentry), true);
            break;
        }
    }
    wofs_memlock_mregion(sb, rg, &irq_flags);

    return 0;
}

/* cur_commit is returned at @entry */
bool wofs_get_cur_commit(struct super_block *sb, struct wofs_inode *pi, enum wofs_entry_type type, struct wofs_mentry *entry)
{
    bool commit_found = false;
    struct wofs_mregion *rg;

    rg = wofs_get_region_by_ino(sb, pi->ino);
    if (rg->ino == pi->ino) /* Cur Commit */
    {
        switch (type) {
        case SET_ATTR:
            if (rg->last_valid_setattr != (u8)-1) {
                memcpy_mcsafe(entry, &rg->entries[rg->last_valid_setattr], sizeof(struct wofs_mentry));
                commit_found = true;
            }
            break;
        case LINK_CHANGE:
            if (rg->last_valid_linkchange != (u8)-1) {
                memcpy_mcsafe(entry, &rg->entries[rg->last_valid_linkchange], sizeof(struct wofs_mentry));
                commit_found = true;
            }
            break;
        default:
            break;
        }
    }

    return commit_found;
}

/* ======================= ANCHOR: commit newattr ========================= */
int wofs_commit_newattr_innvm(struct super_block *sb, struct wofs_inode *pi)
{
    struct wofs_mentry entry;
    struct wofs_setattr_entry *setattr;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    bool commit_found = false;

    setattr = &entry.entry.setattr;

    commit_found = wofs_get_cur_commit(sb, pi, SET_ATTR, &entry);
    if (!commit_found) {
        setattr->mode = pi->i_mode;
        setattr->gid = pi->i_gid;
        setattr->uid = pi->i_uid;
        setattr->mtime = pi->i_mtime;
        setattr->atime = pi->i_atime;
        setattr->ctime = pi->i_ctime;
        setattr->size = pi->i_size;
    }

    entry.type = SET_ATTR;
    setattr->tstamp = get_version(sbi);

    wofs_do_commit_inode(sb, pi->ino, &entry);

    return 0;
}

int wofs_commit_newattr_indram(struct super_block *sb, struct inode *inode)
{
    struct wofs_mentry entry;
    struct wofs_setattr_entry *setattr;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    INIT_TIMING(commit_newattr);

    WOFS_START_TIMING(commit_newattr_t, commit_newattr);

    setattr = &entry.entry.setattr;

    setattr->mode = cpu_to_le16(inode->i_mode);
    setattr->gid = cpu_to_le32(i_gid_read(inode));
    setattr->uid = cpu_to_le32(i_uid_read(inode));
    setattr->mtime = cpu_to_le32(inode->i_mtime.tv_sec);
    setattr->atime = cpu_to_le32(inode->i_atime.tv_sec);
    setattr->ctime = cpu_to_le32(inode->i_ctime.tv_sec);
    setattr->size = cpu_to_le64(inode->i_size);

    entry.type = SET_ATTR;
    setattr->tstamp = get_version(sbi);

    wofs_do_commit_inode(sb, inode->i_ino, &entry);
    WOFS_END_TIMING(commit_newattr_t, commit_newattr);
}

/* automatically update attr based on whether the file (ino) is opened */
int wofs_commit_newattr(struct super_block *sb, u64 ino)
{
    struct wofs_inode *pi;
    struct inode *inode = NULL;

    pi = wofs_get_inode_by_ino(sb, ino);
    inode = wofs_iget_opened(sb, ino);

    wofs_dbgv("%s: inode %d is open: %s\n", __func__, ino, inode != NULL ? "true" : "false");
    /* FIXME: apply haddr here */
    if (inode) {
        wofs_commit_newattr_indram(sb, inode);
        iput(inode);
    } else {
        wofs_commit_newattr_innvm(sb, pi);
    }

    return 0;
}

/* ======================= ANCHOR: commit sizechange ========================= */
/* used only for wofs_setsize(), inode must be opened */
int wofs_commit_sizechange(struct super_block *sb, struct inode *inode, loff_t ia_size)
{
    struct wofs_mentry entry;
    struct wofs_setattr_entry *setattr;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_inode_info_header *sih = WOFS_IH(inode);
    struct wofs_inode *pi;

    pi = wofs_get_inode(sb, inode);

    setattr = &entry.entry.setattr;
    entry.type = SET_ATTR;

    setattr->mode = cpu_to_le16(inode->i_mode);
    setattr->gid = cpu_to_le32(i_gid_read(inode));
    setattr->uid = cpu_to_le32(i_uid_read(inode));
    setattr->mtime = cpu_to_le32(inode->i_mtime.tv_sec);
    setattr->atime = cpu_to_le32(inode->i_atime.tv_sec);
    setattr->ctime = cpu_to_le32(inode->i_ctime.tv_sec);
    setattr->size = cpu_to_le64(ia_size);
    setattr->tstamp = get_version(sbi);

    wofs_do_commit_inode(sb, pi->ino, &entry);

    return 0;
}

/* ======================= ANCHOR: commit linkchange ========================= */
int wofs_commit_linkchange_indram(struct super_block *sb, struct inode *inode)
{
    struct wofs_mentry entry;
    struct wofs_linkchange_entry *linkchange;
    struct wofs_sb_info *sbi = WOFS_SB(sb);

    entry.type = LINK_CHANGE;
    linkchange = &entry.entry.linkchange;
    linkchange->tstamp = get_version(sbi);
    linkchange->links = cpu_to_le16(inode->i_link);
    linkchange->ctime = cpu_to_le32(inode->i_ctime.tv_sec);

    wofs_do_commit_inode(sb, inode->i_ino, &entry);

    return 0;
}

int wofs_commit_linkchange_innvm(struct super_block *sb, struct wofs_inode *pi)
{
    struct wofs_mentry entry;
    struct wofs_linkchange_entry *linkchange;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    bool commit_found = false;

    linkchange = &entry.entry.linkchange;
    commit_found = wofs_get_cur_commit(sb, pi, LINK_CHANGE, &entry);
    if (!commit_found) {
        linkchange->ctime = cpu_to_le32(pi->i_ctime);
        linkchange->links = cpu_to_le16(pi->i_links_count);
    }
    entry.type = LINK_CHANGE;
    linkchange->tstamp = get_version(sbi);

    wofs_do_commit_inode(sb, pi->ino, &entry);

    return 0;
}

int wofs_commit_linkchange(struct super_block *sb, u64 ino)
{
    struct wofs_inode *pi;
    struct inode *inode = NULL;

    pi = wofs_get_inode_by_ino(sb, ino);
    inode = wofs_iget_opened(sb, ino);

    wofs_info("%s: inode %d is open: %s\n", __func__, ino, inode != NULL ? "true" : "false");

    if (inode) {
        wofs_commit_linkchange_indram(sb, inode);
        iput(inode);
    } else {
        wofs_commit_linkchange_innvm(sb, pi);
    }

    return 0;
}

/* ======================= ANCHOR: commit state ========================= */
int wofs_commit_inode_state(struct super_block *sb, struct wofs_inode_state *state)
{
    struct wofs_mentry entry;
    struct wofs_setattr_entry *setattr;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_inode *pi = NULL;

    pi = wofs_get_inode_by_ino(sb, state->ino);

    setattr = &entry.entry.setattr;
    entry.type = SET_ATTR;

    setattr->mode = cpu_to_le16(state->mode);
    setattr->gid = cpu_to_le32(state->gid);
    setattr->uid = cpu_to_le32(state->uid);
    setattr->mtime = cpu_to_le32(state->mtime);
    setattr->atime = cpu_to_le32(state->atime);
    setattr->ctime = cpu_to_le32(state->ctime);
    setattr->size = cpu_to_le64(state->size);

    setattr->tstamp = cpu_to_le64(get_version(sbi));
    wofs_do_commit_inode(sb, pi->ino, &entry);

    return 0;
}

/* ======================= ANCHOR: Transactions ========================= */
struct wofs_journal *wofs_get_journal_by_txid(struct super_block *sb, int txid)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    return (struct wofs_journal *)(sbi->norm_layout.j_addr + txid * WOFS_JOURNAL_SIZE);
}

struct wofs_jentry *wofs_get_jentry_by_slotid(struct super_block *sb, int txid, int slotid)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_journal *jnl = wofs_get_journal_by_txid(sb, txid);
    u64 jcur;
    int cnt = 0;

    traverse_journal_entry(sbi, jcur, jnl)
    {
        if (cnt == slotid) {
            break;
        }
        cnt++;
    }

    return (struct wofs_jentry *)jcur;
}

void wofs_flush_journal_in_batch(struct super_block *sb, u64 jhead, u64 jtail)
{
    /* flush journal log entries in batch */
    if (jhead < jtail) {
        wofs_flush_buffer(jhead, jtail - jhead, 0);
    } else { /* circular */
        /* head to end */
        wofs_flush_buffer(jhead,
                        WOFS_JOURNAL_SIZE - (jhead & ~PAGE_MASK), 0);

        /* start to tail */
        wofs_flush_buffer((void *)((u64)jtail & PAGE_MASK),
                        jtail & ~PAGE_MASK, 0);
    }
    PERSISTENT_BARRIER();
}

enum wofs_ji_obj_type {
    JI_PI = 0,
    JI_PD,
    JI_PD_NEW,
    JI_PI_PAR,
    JI_PI_NEW,
    JI_MAX
};

int wofs_tx_args_map[][WOFS_MAX_OBJ_INVOVED] = {
    [IDLE] { JI_MAX, JI_MAX, JI_MAX, JI_MAX, JI_MAX },
    [CREATE] { JI_PI, JI_PD, JI_PI_PAR, JI_MAX, JI_MAX },
    [MKDIR] { JI_PI, JI_PD, JI_PI_PAR, JI_MAX, JI_MAX },
    [LINK] { JI_PI, JI_PD, JI_PI_PAR, JI_MAX, JI_MAX },
    [SYMLINK] { JI_PI, JI_PD, JI_PI_PAR, JI_PD_NEW, JI_MAX },
    [UNLINK] { JI_PI, JI_PD, JI_PI_PAR, JI_MAX, JI_MAX },
    [RENAME] { JI_PI, JI_PD, JI_PD_NEW, JI_PI_PAR, JI_PI_NEW },
};

struct wofs_jentry_info *wofs_tx_get_ji_from_tx_info(struct wofs_tx_info *info,
                                                 enum wofs_ji_obj_type obj_type)
{
    switch (obj_type) {
    case JI_PI:
        return &info->ji_pi;
    case JI_PD:
        return &info->ji_pd;
    case JI_PD_NEW:
        return &info->ji_pd_new;
    case JI_PI_PAR:
        return &info->ji_pi_par;
    case JI_PI_NEW:
        return &info->ji_pi_new;
    default:
        return NULL;
    }
    return NULL;
}

int wofs_tx_assign_inode_to_ji(struct super_block *sb, struct wofs_jentry_info *ji, struct wofs_inode *pi)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_jentry *je = &ji->jentry;
#ifndef CONFIG_FINEGRAIN_JOURNAL
    /* pi is pesudo */
    je->jinode.i_flags = pi->i_flags;
    je->jinode.i_size = pi->i_size;
    je->jinode.i_ctime = pi->i_ctime;
    je->jinode.i_mtime = pi->i_mtime;
    je->jinode.i_atime = pi->i_atime;
    je->jinode.i_mode = pi->i_mode;
    je->jinode.i_links_count = pi->i_links_count;
    je->jinode.i_xattr = pi->i_xattr;
    je->jinode.i_uid = pi->i_uid;
    je->jinode.i_gid = pi->i_gid;
    je->jinode.i_generation = pi->i_generation;
    je->jinode.i_create_time = pi->i_create_time;
    je->jinode.ino = pi->ino;
    je->jinode.h_addr = pi->h_addr;
    je->jinode.tstamp = pi->tstamp;
    je->jinode.dev.rdev = pi->dev.rdev;
#else
    /* pi is nvmm addr */
    je->data = TRANS_ADDR_TO_OFS(sbi, pi);
#endif

    return 0;
}

int wofs_tx_assign_dentry_to_ji(struct super_block *sb, struct wofs_jentry_info *ji, struct wofs_dentry *pd)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_jentry *je = &ji->jentry;

#ifndef CONFIG_FINEGRAIN_JOURNAL
    /* pd is pesudo */
    je->jdentry.name_len = pd->name_len;
    je->jdentry.links_count = pd->links_count;
    je->jdentry.mtime = pd->mtime;
    je->jdentry.ino = pd->ino;
    je->jdentry.tstamp = pd->tstamp;
    strcpy(je->jdentry.name, pd->name);
#else
    /* pd is nvmm addr */
    je->data = TRANS_ADDR_TO_OFS(sbi, pd);
#endif
    return 0;
}

int do_start_tx(struct super_block *sb, int txid, struct wofs_tx_info *info)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_journal *jnl;
    struct wofs_jentry_info *ji;
    struct wofs_jentry *je;
    u64 jhead, jtail, jend, jstart, jcur;
    unsigned long irq_flags = 0;
    int slotid;

    jnl = wofs_get_journal_by_txid(sb, txid);
    wofs_memunlock_journal(sb, jnl, &irq_flags);
    /* write type */
    jnl->jhdr.jtype = info->jtype;

    /* write jentries */
    jhead = TRANS_OFS_TO_ADDR(sbi, jnl->jhdr.jofs_head);
    jtail = TRANS_OFS_TO_ADDR(sbi, jnl->jhdr.jofs_tail);
    jstart = TRANS_OFS_TO_ADDR(sbi, jnl->jhdr.jofs_start);
    jend = TRANS_OFS_TO_ADDR(sbi, jnl->jhdr.jofs_end);

    if (jhead != jtail) {
        BUG_ON(1);
    }

    jcur = jhead;

    traverse_tx_info(ji, slotid, info)
    {
        if (ji->valid) {
            je = &ji->jentry;
            if (jcur + sizeof(struct wofs_jentry) > jend) {
                jcur = jstart;
            }
            memcpy_to_pmem_nocache((void *)jcur, je, sizeof(struct wofs_jentry));
            jcur += sizeof(struct wofs_jentry);
        }
    }

    jtail = jcur;

    /* commit */
    jnl->jhdr.jofs_tail = TRANS_ADDR_TO_OFS(sbi, jtail);
    wofs_flush_buffer(&jnl->jhdr, sizeof(struct wofs_jheader), true);

    wofs_memlock_journal(sb, jnl, &irq_flags);

    return 0;
}

static bool wofs_tx_obj_is_inode(enum wofs_ji_obj_type obj_type)
{
    return obj_type == JI_PI || obj_type == JI_PI_PAR || obj_type == JI_PI_NEW;
}

static bool wofs_tx_obj_is_dentry(enum wofs_ji_obj_type obj_type)
{
    return obj_type == JI_PD || obj_type == JI_PD_NEW;
}

static int wofs_tx_cnt_args(enum wofs_journal_type jtype)
{
    int *args = wofs_tx_args_map[jtype];
    int i;
    int cnt = 0;

    for (i = 0; i < WOFS_MAX_OBJ_INVOVED; i++) {
        if (args[i] != JI_MAX) {
            cnt++;
        }
    }

    return cnt;
}

int wofs_start_tx(struct super_block *sb, enum wofs_journal_type jtype, ...)
{
    va_list valist;
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_tx_info info;
    struct wofs_jentry_info *ji;
    enum wofs_ji_obj_type ji_obj_type;
    struct wofs_inode *pi;
    struct wofs_dentry *pd;
    struct wofs_journal *jnl;
    bool journal_started = false;
    int txid_cmt = -1;
    int i, txid, start_txid;
    int objs_cnt;

    if (jtype == IDLE) {
        return -1;
    }

    /* Build tx info*/
    objs_cnt = wofs_tx_cnt_args(jtype);
    va_start(valist, objs_cnt);

    /* invalid all entry */
    for (i = 0; i < WOFS_MAX_OBJ_INVOVED; i++) {
        ji = wofs_tx_get_ji_from_tx_info(&info, (enum wofs_ji_obj_type)i);
        ji->valid = false;
    }

    /* valid specific entry */
    for (i = 0; i < objs_cnt; i++) {
        ji_obj_type = wofs_tx_args_map[jtype][i];
        ji = wofs_tx_get_ji_from_tx_info(&info, ji_obj_type);
        ji->valid = true;
        if (wofs_tx_obj_is_inode(ji_obj_type)) {
            pi = va_arg(valist, struct wofs_inode *);
            ji->jentry.type = J_INODE;
            wofs_tx_assign_inode_to_ji(sb, ji, pi);
        } else if (wofs_tx_obj_is_dentry(ji_obj_type)) {
            pd = va_arg(valist, struct wofs_dentry *);
            ji->jentry.type = J_DENTRY;
            wofs_tx_assign_dentry_to_ji(sb, ji, pd);
        }
    }

    /* assign journal type */
    info.jtype = jtype;

    /* find a journal to append txinfo */
    while (!journal_started) {
        txid = wofs_get_cpuid(sb) * WOFS_PERCORE_JSLOTS;
        start_txid = txid;
        do {
            jnl = wofs_get_journal_by_txid(sb, txid);
            use_journal(sb, txid);
            if (jnl->jhdr.jtype == IDLE) {
                do_start_tx(sb, txid, &info);
                txid_cmt = txid;
                journal_started = true;
                unuse_journal(sb, txid);
                break;
            }
            unuse_journal(sb, txid);
            txid = (txid + 1) % sbi->norm_layout.j_slots;
        } while (txid != start_txid);
    }

out:
    va_end(valist);
    return txid_cmt;
}

int wofs_finish_tx(struct super_block *sb, int txid)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_journal *jnl;
    unsigned long irq_flags = 0;

    jnl = wofs_get_journal_by_txid(sb, txid);
    use_journal(sb, txid);
    wofs_memunlock_journal(sb, jnl, &irq_flags);
    jnl->jhdr.jtype = IDLE;
    wofs_flush_buffer(jnl, sizeof(struct wofs_jheader), true);
    jnl->jhdr.jofs_head = jnl->jhdr.jofs_tail;
    wofs_flush_buffer(jnl, sizeof(struct wofs_jheader), true);
    wofs_memlock_journal(sb, jnl, &irq_flags);
    unuse_journal(sb, txid);

    return 0;
}

int wofs_reinit_journal(struct super_block *sb, struct wofs_journal *jnl)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);

    jnl->jhdr.jtype = IDLE;
    jnl->jhdr.jofs_start = TRANS_ADDR_TO_OFS(sbi, (u64)jnl + sizeof(struct wofs_jheader));
    jnl->jhdr.jofs_end = jnl->jhdr.jofs_start + sizeof(struct wofs_jbody);

    jnl->jhdr.jofs_head = jnl->jhdr.jofs_start;
    jnl->jhdr.jofs_tail = jnl->jhdr.jofs_start;

    return 0;
}

/* clean unused pending states caused by find_gaps */
int wofs_stablisze_meta(struct super_block *sb)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    struct wofs_header *hdr;
    struct wofs_layout_info *layout;
    u64 addr;
    int cpuid = 0;
    unsigned long irq_flags = 0;

    for (cpuid = 0; cpuid < sbi->cpus; cpuid++) {
        layout = &sbi->layouts[cpuid];
        wofs_memunlock_range(sb, (void *)sbi->norm_layout.sm_addr, sbi->norm_layout.sm_size, &irq_flags);
        traverse_layout_blks_reverse(addr, layout)
        {
            hdr = sm_get_hdr_by_addr(sb, addr);
            if (hdr->valid == HDR_PENDING) {
                hdr->valid = HDR_INVALID;
                wofs_flush_buffer(hdr, sizeof(struct wofs_header), false);
            }
        }
        wofs_memlock_range(sb, (void *)sbi->norm_layout.sm_addr, sbi->norm_layout.sm_size, &irq_flags);
        PERSISTENT_BARRIER();
    }
}

int wofs_format_meta(struct super_block *sb)
{
    struct wofs_sb_info *sbi = WOFS_SB(sb);
    unsigned long irq_flags = 0;
    struct wofs_header *hdr;
    struct wofs_mregion *rg;
    struct wofs_journal *jnl;
    unsigned long bid, rgid, txid;

    if (ENABLE_META_PACK(sb)) {
        /* Format Bitmaps for Two-Layer Allocator */
        wofs_memunlock_range(sb, (void *)sbi->pack_layout.bm_start , sbi->pack_layout.bm_size, &irq_flags);
        memset_nt_large((void *)sbi->pack_layout.bm_start , 0, sbi->pack_layout.bm_size);
        wofs_memlock_range(sb, (void *)sbi->pack_layout.bm_start , sbi->pack_layout.bm_size, &irq_flags);
    } else {
        /* Step 1: Format Inode Table */
        wofs_memunlock_range(sb, (void *)sbi->norm_layout.ino_tab_addr, sbi->norm_layout.ino_tab_size, &irq_flags);
        memset_nt_large((void *)sbi->norm_layout.ino_tab_addr, 0, sbi->norm_layout.ino_tab_size);
        wofs_memlock_range(sb, sbi->norm_layout.ino_tab_addr, sbi->norm_layout.ino_tab_size, &irq_flags);

        /* Step 2: Format Summary Headers  */
        if (ENABLE_META_LOCAL(sb)) {
            wofs_memunlock_range(sb, (void *)sbi->norm_layout.sm_addr, sbi->norm_layout.sm_size, &irq_flags);
            memset_nt_large((void *)sbi->norm_layout.sm_addr, 0, sbi->norm_layout.sm_size);
            for (bid = 0; bid < sbi->d_blks; bid++) {
                hdr = sm_get_hdr_by_blk(sb, bid);
                if (hdr->valid != HDR_INVALID) {
                    wofs_info("Not Clean\n");
                }
                hdr->valid = HDR_PENDING;
            }
            wofs_flush_buffer((void *)sbi->norm_layout.sm_addr, sbi->norm_layout.sm_size, false);
            wofs_memlock_range(sb, (void *)sbi->norm_layout.sm_addr, sbi->norm_layout.sm_size, &irq_flags);
        } else {
            // TODO: Implement MAGIC number to prevent all valid at init
            wofs_memunlock_range(sb, (void *)sbi->norm_layout.sm_addr, sbi->norm_layout.sm_size, &irq_flags);
            for (bid = 0; bid < sbi->d_blks; bid++) {
                hdr = sm_get_hdr_by_blk(sb, bid);
                hdr->valid = HDR_PENDING;
            }
            wofs_flush_buffer(sbi->norm_layout.sm_addr, sbi->norm_layout.sm_size, false);
            wofs_memlock_range(sb, (void *)sbi->norm_layout.sm_addr, sbi->norm_layout.sm_size, &irq_flags);
        }
        wofs_dbgv("entries: %llu\n", sbi->norm_layout.sm_size / sizeof(struct wofs_header));
        wofs_dbgv("sbi->d_blks: %llu\n", sbi->d_blks);

        /* Step 3: Format Jentry */
        wofs_memunlock_range(sb, (void *)sbi->norm_layout.j_addr, sbi->norm_layout.j_size, &irq_flags);
        for (txid = 0; txid < sbi->norm_layout.j_slots; txid++) {
            jnl = wofs_get_journal_by_txid(sb, txid);
            wofs_reinit_journal(sb, jnl);
            wofs_flush_buffer((void *)jnl, WOFS_JOURNAL_SIZE, false);
        }
        wofs_memlock_range(sb, (void *)sbi->norm_layout.j_addr, sbi->norm_layout.j_size, &irq_flags);

        /* Step 4: Format Regions */
        wofs_memunlock_range(sb, (void *)sbi->norm_layout.rg_addr, sbi->pack_layout.obj_mgr, &irq_flags);
        for (rgid = 0; rgid < sbi->norm_layout.rg_slots; rgid++) {
            rg = wofs_get_region_by_rgid(sb, rgid);
            rg->applying = 0;
            wofs_reinit_region(sb, rg);
            wofs_flush_buffer((void *)rg, sizeof(struct wofs_mregion), false);
        }
        wofs_memlock_range(sb, (void *)sbi->norm_layout.rg_addr, sbi->pack_layout.obj_mgr, &irq_flags);
    }
    wofs_info("meta format done.\n");
    return 0;
}