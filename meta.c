#include "hunter.h"

/* ======================= ANCHOR: Summary Header ========================= */

/* start of pblk */
u64 sm_get_addr_by_hdr(struct super_block *sb, u64 hdr)
{
    struct hk_sb_info *sbi = HK_SB(sb);
#ifndef CONFIG_LAYOUT_TIGHT
    u64 blk = (hdr - sbi->sm_addr) / sizeof(struct hk_header);
    return sbi->d_addr + (blk * HK_PBLK_SZ);
#else
    return hdr + sizeof(struct hk_header) - HK_PBLK_SZ;
#endif 
}

struct hk_header *sm_get_hdr_by_blk(struct super_block *sb, u64 blk)
{
    struct hk_sb_info *sbi = HK_SB(sb);
#ifndef CONFIG_LAYOUT_TIGHT
    return (struct hk_header *)(sbi->sm_addr + blk * sizeof(struct hk_header));
#else
    return (struct hk_header *)(sbi->d_addr + (blk + 1) * HK_PBLK_SZ - sizeof(struct hk_header));
#endif 
}

struct hk_header *sm_get_hdr_by_addr(struct super_block *sb, u64 addr)
{
    u64 blk;
    struct hk_sb_info *sbi = HK_SB(sb);

    if (addr < sbi->d_addr) {
        hk_info("%s: Invalid Addr\n", __func__);
        BUG_ON(1);
    }
    
    blk = (addr - sbi->d_addr) / HK_PBLK_SZ;
    
    hk_dbgv("sbi->sm_addr: %llx, %d, %d\n", sbi->sm_addr, sizeof(struct hk_header), blk * sizeof(struct hk_header));
    
    return sm_get_hdr_by_blk(sb, blk);
}

struct hk_layout_info* sm_get_layout_by_hdr(struct super_block *sb, u64 hdr)
{
    int cpuid;
    struct hk_sb_info *sbi = HK_SB(sb);
    u64 addr = sm_get_addr_by_hdr(sb, hdr);
    u64 size_per_layout = _round_down(sbi->d_size / sbi->num_layout, HK_PBLK_SZ);

    cpuid = (addr - sbi->d_addr) / size_per_layout;
    
    /* cpuid could larger that (sbi->num_layout - 1) */
    cpuid = cpuid >= sbi->num_layout ? cpuid - 1 : cpuid;

    return &sbi->layouts[cpuid];
}

/* TODO: Not protect hdr in remove function */
int sm_remove_hdr(struct super_block *sb, struct hk_inode *pi, struct hk_header *hdr) 
{
    struct hk_sb_info           *sbi = HK_SB(sb);
    bool                        is_hdr_unlock_already = false;
    unsigned long               irq_flags = 0;

    if (TRANS_OFS_TO_ADDR(sbi, hdr->ofs_prev) == pi) {
        hk_memunlock_inode(sb, pi, &irq_flags);
        pi->h_addr = hdr->ofs_next;
        hk_memlock_inode(sb, pi, &irq_flags);
    }
    else {
        hk_memunlock_hdr(sb, hdr, &irq_flags);
        ((struct hk_header *)TRANS_OFS_TO_ADDR(sbi, hdr->ofs_prev))->ofs_next = hdr->ofs_next;
        is_hdr_unlock_already = true;
    }
    
    if (!is_hdr_unlock_already) {
        hk_memunlock_hdr(sb, hdr, &irq_flags);
    }

    if (TRANS_OFS_TO_ADDR(sbi, hdr->ofs_next) != NULL) {
        ((struct hk_header *)TRANS_OFS_TO_ADDR(sbi, hdr->ofs_next))->ofs_prev = hdr->ofs_prev;
    }
    hdr->ofs_next = NULL;
    hdr->ofs_prev = NULL;
    hk_memlock_hdr(sb, hdr, &irq_flags);

    return 0;
}

/* TODO: Not protect hdr in insert function */
int sm_insert_hdr(struct super_block *sb, struct hk_inode *pi, struct hk_header *hdr) 
{
    struct hk_sb_info           *sbi = HK_SB(sb);
    unsigned long               irq_flags = 0;

    /* Write Hdr, then persist it */
    hk_memunlock_hdr(sb, hdr, &irq_flags);
    /* Change the link */
    hdr->ofs_prev = TRANS_ADDR_TO_OFS(sbi, pi);
    hdr->ofs_next = pi->h_addr;
    hk_memunlock_inode(sb, pi, &irq_flags);
    if (pi->h_addr != NULL) {
        ((struct hk_header *)TRANS_OFS_TO_ADDR(sbi, pi->h_addr))->ofs_prev = TRANS_ADDR_TO_OFS(sbi, hdr);
    }
    pi->h_addr = TRANS_ADDR_TO_OFS(sbi, hdr);
    hk_memlock_inode(sb, pi, &irq_flags);
    hk_memlock_hdr(sb, hdr, &irq_flags);
    return 0;
}

// TODO: Timer
int sm_invalid_hdr(struct super_block *sb, u64 blk_addr, u64 ino)
{
    /*! Note: Do not update tstamp in invalid process, since version control */
    struct hk_inode         *pi;
    struct inode            *inode;
    struct hk_header        *hdr;
    struct hk_layout_info   *layout;
    struct hk_sb_info       *sbi = HK_SB(sb);
    unsigned long           irq_flags = 0;
    INIT_TIMING(invalid_time);

    HK_START_TIMING(sm_invalid_t, invalid_time);
    pi = hk_get_inode_by_ino(sb, ino);
    hdr = sm_get_hdr_by_addr(sb, blk_addr);
    
    sm_remove_hdr(sb, pi, hdr);

    hk_memunlock_hdr(sb, hdr, &irq_flags);
    hdr->valid = 0;
#ifndef CONFIG_LAYOUT_TIGHT
    /* this might be relatively slow */
    hk_flush_buffer(hdr, sizeof(struct hk_header), true);
#else
    /* flush outside with blk */
#endif
    hk_memlock_hdr(sb, hdr, &irq_flags);

    layout = sm_get_layout_by_hdr(sb, (u64)hdr);

    ind_update(&layout->ind, INVALIDATE_BLK, 1);
    HK_END_TIMING(sm_invalid_t, invalid_time);
    return 0;
}

// TODO: Timer
int sm_valid_hdr(struct super_block *sb, u64 blk_addr, u64 ino, u64 f_blk, u64 tstamp)
{
    struct hk_inode         *pi;
    struct hk_header        *hdr;
    struct hk_layout_info   *layout;
    struct hk_sb_info       *sbi = HK_SB(sb);
    struct inode            *inode = NULL; 
    u64                     blk;
    unsigned long           irq_flags = 0;
    INIT_TIMING(valid_time);

    HK_START_TIMING(sm_valid_t, valid_time);
    pi = hk_get_inode_by_ino(sb, ino);
    if (!pi)
        return -1;
    
    hdr = sm_get_hdr_by_addr(sb, blk_addr);
    
    if (hdr->f_blk == f_blk && 
        hdr->ino == ino && 
        hdr->valid == 1)     /*! No need to update */
    {
        hk_warn("hdr@0x%llx does not need to update\n", (u64)hdr);
        return 0;
    }
    
    // hk_info("hdr at: 0x%llx\n", (u64)hdr);

    /* Write Hdr, then persist it */
    hk_memunlock_hdr(sb, hdr, &irq_flags);
    hdr->ino = ino;
    hdr->tstamp = tstamp;
    hdr->f_blk = f_blk;
    /* Change the link */
    hk_memlock_hdr(sb, hdr, &irq_flags);

    sm_insert_hdr(sb, pi, hdr);

    hk_memunlock_hdr(sb, hdr, &irq_flags);
    hdr->valid = 1;
#ifndef CONFIG_LAYOUT_TIGHT
    /* this might be relatively slow */
    hk_flush_buffer(hdr, sizeof(struct hk_header), true);
#else
    /* flush outside with blk */
#endif
    hk_memlock_hdr(sb, hdr, &irq_flags);
    
    layout = sm_get_layout_by_hdr(sb, (u64)hdr);
    
    /* Remove Prep from Layouts */
    blk = hk_get_dblk_by_addr(sbi, blk_addr);
    hk_range_remove(sb, &layout->prep_list, blk);

    ind_update(&layout->ind, VALIDATE_BLK, 1);

    HK_END_TIMING(sm_valid_t, valid_time);
    return 0;
}

/* ======================= ANCHOR: Meta Regions ========================= */

struct hk_mregion* hk_get_region_by_rgid(struct super_block *sb, int rgid)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    return (struct hk_mregion*)(sbi->rg_addr + rgid * sizeof(struct hk_mregion));
}

struct hk_mregion* hk_get_region_by_ino(struct super_block *sb, u64 ino)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    int rgid;
    
    rgid = ino % sbi->rg_slots;
    
    return hk_get_region_by_rgid(sb, rgid);
} 

/* Make sure region is memunlocked */
int hk_reinit_region(struct super_block *sb, struct hk_mregion *rg)
{
    rg->ino = cpu_to_le64((u64)-1);
    rg->last_valid_setattr = cpu_to_le64((u8)-1);
    rg->last_valid_linkchange = cpu_to_le64((u8)-1);
    return 0;
}

/* pi should be unlocked */
void hk_apply_entry(struct super_block *sb, struct hk_inode *pi, struct hk_mentry *entry) 
{
    switch (entry->type)
    {
    case SET_ATTR:
        pi->i_atime  = pi->i_atime >= entry->entry.setattr.atime ? 
                       pi->i_atime : entry->entry.setattr.atime;
        pi->i_ctime  = pi->i_ctime >= entry->entry.setattr.ctime ? 
                       pi->i_ctime : entry->entry.setattr.ctime;
        pi->i_mtime  = pi->i_mtime >= entry->entry.setattr.mtime ? 
                       pi->i_mtime : entry->entry.setattr.mtime;
        pi->i_gid    = entry->entry.setattr.gid;
        pi->i_uid    = entry->entry.setattr.uid;
        pi->i_size   = entry->entry.setattr.size;
        pi->i_mode   = entry->entry.setattr.mode; 
        pi->tstamp   = pi->tstamp >= entry->entry.setattr.tstamp ? 
                       pi->tstamp : entry->entry.setattr.tstamp;
        break;
    case LINK_CHANGE:
        pi->i_links_count = entry->entry.linkchange.links;
        pi->i_ctime = pi->i_ctime >= entry->entry.linkchange.ctime ? 
                      pi->i_ctime : entry->entry.linkchange.ctime;
        pi->tstamp  = pi->tstamp >= entry->entry.linkchange.tstamp ? 
                      pi->tstamp : entry->entry.linkchange.tstamp;
        break;
    default:
        break;
    }    
}

/* no need to handle memlock or unlock */
void hk_apply_entry_once(struct super_block *sb, struct hk_inode *pi, struct hk_mentry *entry) 
{
    struct hk_mregion *rg;    
    unsigned long irq_flags = 0;

    hk_memunlock_inode(sb, pi, &irq_flags);
    hk_apply_entry(sb, pi, entry);
    hk_memlock_inode(sb, pi, &irq_flags);

    rg = hk_get_region_by_ino(sb, le64_to_cpu(pi->ino));
    
    hk_memunlock_mregion(sb, rg, &irq_flags);
    switch (entry->type)
    {
    case SET_ATTR:
        rg->last_valid_setattr = (u8)-1;
        break;
    case LINK_CHANGE:
        rg->last_valid_linkchange = (u8)-1;
        break;
    default:
        break;
    }
    hk_memlock_mregion(sb, rg, &irq_flags);
}


int hk_applying_region(struct super_block *sb, struct hk_mregion *rg)
{
    u32 ino = rg->ino;
    int slotid;
    struct hk_inode *pi = hk_get_inode_by_ino(sb, ino); 
    unsigned long irq_flags = 0;
    
    if (!pi->valid) {
        return -1;
    }

    hk_memunlock_mregion(sb, rg, &irq_flags);
    rg->applying = 1;    
    hk_memlock_mregion(sb, rg, &irq_flags);
    hk_flush_buffer(rg, sizeof(struct hk_mregion), true);

    hk_memunlock_inode(sb, pi, &irq_flags);
    for (slotid = 0; slotid < HK_RG_ENTY_SLOTS; slotid++)
    {
        if (rg->last_valid_setattr == slotid || rg->last_valid_linkchange == slotid)
        {
            hk_apply_entry(sb, pi, &rg->entries[slotid]);
        }
    }
    hk_memlock_inode(sb, pi, &irq_flags);
    hk_flush_buffer(pi, sizeof(struct hk_inode), true);    
    

    hk_memunlock_mregion(sb, rg, &irq_flags);
    rg->applying = 0;    
    hk_memlock_mregion(sb, rg, &irq_flags);
    hk_flush_buffer(rg, sizeof(struct hk_mregion), true);

    /* Invalidate the region */
    hk_reinit_region(sb, rg);

    return 0;
}

/* apply region to pi */
int hk_applying_region_to_inode(struct super_block *sb, struct hk_inode *pi)
{
    struct hk_mentry entry;
    bool             commit_found = false;

    commit_found = hk_get_cur_commit(sb, pi, SET_ATTR, &entry);
    if (commit_found) {
        hk_apply_entry_once(sb, pi, &entry);
    }

    commit_found = hk_get_cur_commit(sb, pi, LINK_CHANGE, &entry);
    if (commit_found) {
        hk_apply_entry_once(sb, pi, &entry);
    }

    return 0;
}

int hk_do_commit_inode(struct super_block *sb, u64 ino, struct hk_mentry *entry)
{
    struct hk_mregion *rg;
    unsigned long irq_flags = 0;
    int slotid;

    rg = hk_get_region_by_ino(sb, ino);
    /* Evict Region */
    if (rg->ino != ino && rg->ino != (u64)-1)
    {
        hk_applying_region(sb, rg);
    }

    hk_memunlock_mregion(sb, rg, &irq_flags);
    rg->ino = ino;

    for (slotid = 0; slotid < HK_RG_ENTY_SLOTS; slotid++)
    {
        if (slotid != rg->last_valid_linkchange && slotid != rg->last_valid_setattr)
        {
            memcpy_to_pmem_nocache(&rg->entries[slotid], entry, sizeof(struct hk_mentry));
            
            PERSISTENT_BARRIER();
            /* Commit The Write */
            switch (entry->type)
            {
            case SET_ATTR:
                rg->last_valid_setattr = slotid;
                break;
            case LINK_CHANGE:
                rg->last_valid_linkchange = slotid;
                break;
            default:
                break;
            }
            hk_flush_buffer(rg, sizeof(struct hk_mentry), true);
            
            // hk_flush_small_buffer(rg, CACHELINE_SIZE, true);
            break;
        }
    }
    hk_memlock_mregion(sb, rg, &irq_flags);

    return 0;
}

/* cur_commit is returned at @entry */
bool hk_get_cur_commit(struct super_block *sb, struct hk_inode *pi, enum hk_entry_type type, struct hk_mentry *entry)
{
    bool commit_found = false;
    struct hk_mregion *rg;

    rg = hk_get_region_by_ino(sb, pi->ino);
    if (rg->ino == pi->ino)      /* Cur Commit */
    {
        switch (type)
        {
        case SET_ATTR:
            if (rg->last_valid_setattr != (u8)-1)
            {
                memcpy_mcsafe(entry, &rg->entries[rg->last_valid_setattr], sizeof(struct hk_mentry));
                commit_found = true;
            }
            break;
        case LINK_CHANGE:
            if (rg->last_valid_linkchange != (u8)-1)
            {
                memcpy_mcsafe(entry, &rg->entries[rg->last_valid_linkchange], sizeof(struct hk_mentry));
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
int hk_commit_newattr_innvm(struct super_block *sb, struct hk_inode *pi)
{
    struct hk_mentry        entry;
    struct hk_setattr_entry *setattr;
    struct hk_sb_info       *sbi = HK_SB(sb);
    bool                    commit_found = false;

    setattr = &entry.entry.setattr;
    
    commit_found = hk_get_cur_commit(sb, pi, SET_ATTR, &entry);
    if (!commit_found) {
        setattr->mode    = pi->i_mode;
        setattr->gid     = pi->i_gid;
        setattr->uid     = pi->i_uid;
        setattr->mtime   = pi->i_mtime;
        setattr->atime   = pi->i_atime;
        setattr->ctime   = pi->i_ctime;
        setattr->size    = pi->i_size;
    }

    entry.type = SET_ATTR;
    setattr->tstamp = get_version(sbi);

    hk_do_commit_inode(sb, pi->ino, &entry);
    
    return 0;
}

int hk_commit_newattr_indram(struct super_block *sb, struct inode *inode)
{
    struct hk_mentry        entry;
    struct hk_setattr_entry *setattr;
    struct hk_sb_info       *sbi = HK_SB(sb);
    
    setattr = &entry.entry.setattr;

    setattr->mode    = cpu_to_le16(inode->i_mode); 
    setattr->gid     = cpu_to_le32(i_gid_read(inode));
    setattr->uid     = cpu_to_le32(i_uid_read(inode));
    setattr->mtime   = cpu_to_le32(inode->i_mtime.tv_sec);
    setattr->atime   = cpu_to_le32(inode->i_atime.tv_sec);
    setattr->ctime   = cpu_to_le32(inode->i_ctime.tv_sec);
    setattr->size    = cpu_to_le64(inode->i_size);

    entry.type = SET_ATTR;
    setattr->tstamp = get_version(sbi);

    hk_do_commit_inode(sb, inode->i_ino, &entry);
}

/* automatically update attr based on whether the file (ino) is opened */
int hk_commit_newattr(struct super_block *sb, u64 ino)
{
    struct hk_inode         *pi;
    struct inode            *inode = NULL;

    pi = hk_get_inode_by_ino(sb, ino);
    inode = hk_iget_opened(sb, ino);

    hk_dbgv("%s: inode %d is open: %s\n", __func__, ino, inode != NULL ? "true" : "false");
    /* FIXME: apply haddr here */
    if (inode) {
        hk_commit_newattr_indram(sb, inode);
        iput(inode);
    }
    else {
        hk_commit_newattr_innvm(sb, pi);
    }
    
    return 0;
}

/* ======================= ANCHOR: commit sizechange ========================= */
/* used only for hk_setsize(), inode must be opened */
int hk_commit_sizechange(struct super_block *sb, struct inode *inode, loff_t ia_size)
{
    struct hk_mentry        entry;
    struct hk_setattr_entry *setattr;
    struct hk_sb_info       *sbi = HK_SB(sb);
    struct hk_inode_info_header *sih = HK_IH(inode);
    struct hk_inode         *pi;

    pi = hk_get_inode(sb, inode);

    setattr = &entry.entry.setattr;
    entry.type = SET_ATTR;

    setattr->mode    = cpu_to_le16(inode->i_mode); 
    setattr->gid     = cpu_to_le32(i_gid_read(inode));
    setattr->uid     = cpu_to_le32(i_uid_read(inode));
    setattr->mtime   = cpu_to_le32(inode->i_mtime.tv_sec);
    setattr->atime   = cpu_to_le32(inode->i_atime.tv_sec);
    setattr->ctime   = cpu_to_le32(inode->i_ctime.tv_sec);
    setattr->size    = cpu_to_le64(ia_size);
    setattr->tstamp  = get_version(sbi);

    hk_do_commit_inode(sb, pi->ino, &entry);  

    return 0;
}

/* ======================= ANCHOR: commit linkchange ========================= */
int hk_commit_linkchange_indram(struct super_block *sb, struct inode *inode)
{
    struct hk_mentry           entry;
    struct hk_linkchange_entry *linkchange;
    struct hk_sb_info          *sbi = HK_SB(sb);

    entry.type = LINK_CHANGE;
    linkchange = &entry.entry.linkchange;
    linkchange->tstamp = get_version(sbi);
    linkchange->links = cpu_to_le16(inode->i_link);
    linkchange->ctime = cpu_to_le32(inode->i_ctime.tv_sec);

    hk_do_commit_inode(sb, inode->i_ino, &entry);
    
    return 0;
}

int hk_commit_linkchange_innvm(struct super_block *sb, struct hk_inode *pi)
{
    struct hk_mentry        entry;
    struct hk_linkchange_entry *linkchange;
    struct hk_sb_info       *sbi = HK_SB(sb);
    bool                    commit_found = false;

    linkchange = &entry.entry.linkchange;
    commit_found = hk_get_cur_commit(sb, pi, LINK_CHANGE, &entry);
    if (!commit_found) {
        linkchange->ctime = cpu_to_le32(pi->i_ctime);
        linkchange->links = cpu_to_le16(pi->i_links_count);
    }
    entry.type = LINK_CHANGE;
    linkchange->tstamp = get_version(sbi);

    hk_do_commit_inode(sb, pi->ino, &entry);
    
    return 0;
}

int hk_commit_linkchange(struct super_block *sb, u64 ino)
{
    struct hk_inode   *pi;
    struct inode      *inode = NULL;

    pi = hk_get_inode_by_ino(sb, ino);
    inode = hk_iget_opened(sb, ino);
    
    hk_info("%s: inode %d is open: %s\n", __func__, ino, inode != NULL ? "true" : "false");

    if (inode) {
        hk_commit_linkchange_indram(sb, inode);
        iput(inode);
    }
    else {
        hk_commit_linkchange_innvm(sb, pi);
    }
    
    return 0;
}

/* ======================= ANCHOR: commit state ========================= */
int hk_commit_inode_state(struct super_block *sb, struct hk_inode_state *state)
{
    struct hk_mentry        entry;
    struct hk_setattr_entry *setattr;
    struct hk_sb_info       *sbi = HK_SB(sb);
    struct hk_inode         *pi = NULL;

    pi = hk_get_inode_by_ino(sb, state->ino);
    
    setattr = &entry.entry.setattr;
    entry.type = SET_ATTR;
    
    setattr->mode    = cpu_to_le16(state->mode);
    setattr->gid     = cpu_to_le32(state->gid);
    setattr->uid     = cpu_to_le32(state->uid);
    setattr->mtime   = cpu_to_le32(state->mtime);
    setattr->atime   = cpu_to_le32(state->atime);
    setattr->ctime   = cpu_to_le32(state->ctime);
    setattr->size    = cpu_to_le64(state->size);

    setattr->tstamp  = cpu_to_le64(get_version(sbi));

    hk_do_commit_inode(sb, pi->ino, &entry);  

    return 0;
}

/* ======================= ANCHOR: Transactions ========================= */
struct hk_journal* hk_get_journal_by_txid(struct super_block *sb, int txid)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    return (struct hk_journal*)(sbi->j_addr + txid * HK_JOURNAL_SIZE);
}

struct hk_jentry* hk_get_jentry_by_slotid(struct super_block *sb, int txid, int slotid)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_journal *jnl = hk_get_journal_by_txid(sb, txid);
    u64 jcur;
    int cnt = 0;

    traverse_journal_entry(sbi, jcur, jnl) {
        if (cnt == slotid) {
            break;
        }
        cnt++;
    }

    return (struct hk_jentry *)jcur;
}

void hk_flush_journal_in_batch(struct super_block *sb, u64 jhead, u64 jtail)
{
	/* flush journal log entries in batch */
	if (jhead < jtail) {
		hk_flush_buffer(jhead, jtail - jhead, 0);
	} 
    else {    /* circular */
		/* head to end */
		hk_flush_buffer(jhead,
			HK_JOURNAL_SIZE - (jhead & ~PAGE_MASK), 0);

		/* start to tail */
		hk_flush_buffer((void*)((u64)jtail & PAGE_MASK),
			jtail & ~PAGE_MASK, 0);
	}
	PERSISTENT_BARRIER();
}

enum hk_ji_obj_type {
    JI_PI = 0,
    JI_PD,
    JI_PD_NEW,
    JI_PI_PAR,
    JI_PI_NEW,
    JI_MAX
};

int hk_tx_args_map[][HK_MAX_OBJ_INVOVED] = {
    [IDLE] {JI_MAX, JI_MAX, JI_MAX, JI_MAX, JI_MAX},
    [CREATE] {JI_PI, JI_PD, JI_PI_PAR, JI_MAX, JI_MAX},
    [MKDIR] {JI_PI, JI_PD, JI_PI_PAR, JI_MAX, JI_MAX},
    [LINK] {JI_PI, JI_PD, JI_PI_PAR, JI_MAX, JI_MAX},
    [SYMLINK] {JI_PI, JI_PD, JI_PI_PAR, JI_PD_NEW, JI_MAX},
    [UNLINK] {JI_PI, JI_PD, JI_PI_PAR, JI_MAX, JI_MAX},
    [RENAME] {JI_PI, JI_PD, JI_PD_NEW, JI_PI_PAR, JI_PI_NEW},
};

struct hk_jentry_info *hk_tx_get_ji_from_tx_info(struct hk_tx_info *info, 
                                                 enum hk_ji_obj_type obj_type)
{
    switch (obj_type)
    {
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

int hk_tx_assign_inode_to_ji(struct super_block *sb, struct hk_jentry_info *ji, struct hk_inode *pi)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_jentry *je = &ji->jentry;
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

int hk_tx_assign_dentry_to_ji(struct super_block *sb, struct hk_jentry_info *ji, struct hk_dentry *pd)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_jentry *je = &ji->jentry;

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

int do_start_tx(struct super_block *sb, int txid, struct hk_tx_info *info)
{
    struct hk_sb_info      *sbi = HK_SB(sb);
    struct hk_journal      *jnl;
    struct hk_jentry_info  *ji;
    struct hk_jentry       *je;
    u64                    jhead, jtail, jend, jstart, jcur;
    unsigned long          irq_flags = 0;
    int slotid;

    jnl = hk_get_journal_by_txid(sb, txid);
    hk_memunlock_journal(sb, jnl, &irq_flags);
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
            if (jcur + sizeof(struct hk_jentry) > jend) {
                jcur = jstart;
            }
            memcpy_to_pmem_nocache((void *)jcur, je, sizeof(struct hk_jentry));
            jcur += sizeof(struct hk_jentry);
        }
    }
    
    jtail = jcur;
    
    /* commit */
    jnl->jhdr.jofs_tail = TRANS_ADDR_TO_OFS(sbi, jtail);
    hk_flush_buffer(&jnl->jhdr, sizeof(struct hk_jheader), true);

    hk_memlock_journal(sb, jnl, &irq_flags);

    return 0;
}

static bool hk_tx_obj_is_inode(enum hk_ji_obj_type obj_type)
{
    return obj_type == JI_PI || obj_type == JI_PI_PAR || obj_type == JI_PI_NEW;
}

static bool hk_tx_obj_is_dentry(enum hk_ji_obj_type obj_type)
{
    return obj_type == JI_PD || obj_type == JI_PD_NEW;
}

static int hk_tx_cnt_args(enum hk_journal_type jtype)
{
    int *args = hk_tx_args_map[jtype];
    int i;
    int cnt = 0;

    for (i = 0; i < HK_MAX_OBJ_INVOVED; i++) {
        if (args[i] != JI_MAX) {
            cnt++;
        }
    }
    
    return cnt;
}

int hk_start_tx(struct super_block *sb, enum hk_journal_type jtype, ...)
{
    va_list               valist;
    struct hk_sb_info     *sbi = HK_SB(sb);
    struct hk_tx_info     info;
    struct hk_jentry_info *ji;
    enum   hk_ji_obj_type ji_obj_type;
    struct hk_inode       *pi;
    struct hk_dentry      *pd;
    struct hk_journal     *jnl;
    bool                  journal_started = false;
    int txid_cmt = -1;
    int i, txid, start_txid;
    int objs_cnt;

    if (jtype == IDLE) {
        return -1;
    }

    /* Build tx info*/
    objs_cnt = hk_tx_cnt_args(jtype);
    va_start(valist, objs_cnt);
    
    /* invalid all entry */
    for (i = 0; i < HK_MAX_OBJ_INVOVED; i++)
    {
        ji = hk_tx_get_ji_from_tx_info(&info, (enum hk_ji_obj_type)i);
        ji->valid = false;
    }

    /* valid specific entry */
    for (i = 0; i < objs_cnt; i++) {
        ji_obj_type = hk_tx_args_map[jtype][i];
        ji = hk_tx_get_ji_from_tx_info(&info, ji_obj_type);
        ji->valid = true;
        if (hk_tx_obj_is_inode(ji_obj_type)) {
            pi = va_arg(valist, struct hk_inode *);
            ji->jentry.type = J_INODE;
            hk_tx_assign_inode_to_ji(sb, ji, pi);
        }
        else if (hk_tx_obj_is_dentry(ji_obj_type)) {
            pd = va_arg(valist, struct hk_dentry *);
            ji->jentry.type = J_DENTRY;
            hk_tx_assign_dentry_to_ji(sb, ji, pd);
        }
    }
    
    /* assign journal type */
    info.jtype = jtype;

    /* find a journal to append txinfo */
    while (!journal_started)
    {
        txid = hk_get_cpuid(sb) * HK_PERCORE_JSLOTS;
        start_txid = txid;
        do {
            jnl = hk_get_journal_by_txid(sb, txid);
            use_journal(sb, txid);
            if (jnl->jhdr.jtype == IDLE) {
                do_start_tx(sb, txid, &info);
                txid_cmt = txid;
                journal_started = true;
                unuse_journal(sb, txid);
                break;    
            }
            unuse_journal(sb, txid);
            txid = (txid + 1) % sbi->j_slots;
        } while (txid != start_txid);
    }

out:
    va_end(valist);
    return txid_cmt;
}

int hk_finish_tx(struct super_block *sb, int txid)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_journal *jnl;
    unsigned long     irq_flags = 0;

    jnl = hk_get_journal_by_txid(sb, txid);
    use_journal(sb, txid);
    hk_memunlock_journal(sb, jnl, &irq_flags);
    jnl->jhdr.jtype = IDLE;
    hk_flush_buffer(jnl, sizeof(struct hk_jheader), true);
    jnl->jhdr.jofs_head = jnl->jhdr.jofs_tail;
    hk_flush_buffer(jnl, sizeof(struct hk_jheader), true);
    hk_memlock_journal(sb, jnl, &irq_flags);
    unuse_journal(sb, txid);

    return 0;
}

int hk_reinit_journal(struct super_block *sb, struct hk_journal *jnl)
{
    struct hk_sb_info *sbi = HK_SB(sb);

    jnl->jhdr.jtype = IDLE;
    jnl->jhdr.jofs_start = TRANS_ADDR_TO_OFS(sbi, (u64)jnl + sizeof(struct hk_jheader));
    jnl->jhdr.jofs_end = jnl->jhdr.jofs_start + sizeof(struct hk_jbody);
    
    jnl->jhdr.jofs_head = jnl->jhdr.jofs_start;
    jnl->jhdr.jofs_tail = jnl->jhdr.jofs_start;
    
    return 0;
}

int hk_format_meta(struct super_block *sb)
{
	struct hk_sb_info 	  *sbi = HK_SB(sb);
	unsigned long 		  irq_flags = 0;
    struct hk_header      *hdr;
    struct hk_mregion     *rg;
    struct hk_journal     *jnl;
    unsigned long bid, rgid, txid;
	
    // TODO: Change Memset_nt to for loop

	/* Step 1: Format Inode Table */
	hk_memunlock_range(sb, (void *)sbi->ino_tab_addr, sbi->ino_tab_size, &irq_flags);
	memset_nt_large((void *)sbi->ino_tab_addr, 0, sbi->ino_tab_size);
	hk_memlock_range(sb, sbi->ino_tab_addr, sbi->ino_tab_size, &irq_flags);
	
	/* Step 2: Format Summary Headers  */
#ifndef CONFIG_LAYOUT_TIGHT
	hk_memunlock_range(sb, (void *)sbi->sm_addr, sbi->sm_size, &irq_flags);
	memset_nt_large((void *)sbi->sm_addr, 0, sbi->sm_size);
	hk_memlock_range(sb, (void *)sbi->sm_addr, sbi->sm_size, &irq_flags);
    for (bid = 0; bid < sbi->d_blks; bid++) {
        hdr = sm_get_hdr_by_blk(sb, bid);
        if (hdr->valid != 0) {
            hk_info("Not Clean\n");
        }
    }
    hk_dbgv("entries: %llu\n", sbi->sm_size / sizeof(struct hk_header));
    /* Not clean ? */
    hk_dbgv("sbi->d_blks: %llu\n", sbi->d_blks);
#else
    // TODO: Implement MAGIC number to prevent all valid at init
    hk_memunlock_range(sb, (void *)sbi->d_addr, sbi->d_size, &irq_flags);
    for (bid = 0; bid < sbi->d_blks; bid++) {
        hdr = sm_get_hdr_by_blk(sb, bid);
        hdr->valid = 0;
    }
    hk_memlock_range(sb, (void *)sbi->d_addr, sbi->d_size, &irq_flags);
    hk_flush_buffer(sbi->d_addr, sbi->d_size, false);
#endif 
	
	/* Step 3: Format Jentry */
	hk_memunlock_range(sb, (void *)sbi->j_addr, sbi->j_size, &irq_flags);
    for (txid = 0; txid < sbi->j_slots; txid++)
    {
        jnl = hk_get_journal_by_txid(sb, txid);
        hk_reinit_journal(sb, jnl);
        hk_flush_buffer((void *)jnl, HK_JOURNAL_SIZE, false);
    }
	hk_memlock_range(sb, (void *)sbi->j_addr, sbi->j_size, &irq_flags);
    
    /* Step 4: Format Regions */
    hk_memunlock_range(sb, (void *)sbi->rg_addr, sbi->rg_size, &irq_flags);
    for (rgid = 0; rgid < sbi->rg_slots; rgid++)
    {
        rg = hk_get_region_by_rgid(sb, rgid);
        rg->applying = 0;
        hk_reinit_region(sb, rg);
        hk_flush_buffer((void *)rg, sizeof(struct hk_mregion), false);
    }
    hk_memlock_range(sb, (void *)sbi->rg_addr, sbi->rg_size, &irq_flags);

    hk_info("meta format done.\n");
	return 0;
}