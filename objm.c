#include "hunter.h"
#include "mt19937ar.h"

/* Global Usage */
int do_reclaim_dram_pkg(struct hk_sb_info *sbi, obj_mgr_t *mgr, u64 pkg_addr, u16 pkg_type);
static int reserve_pkg_space(obj_mgr_t *mgr, u64 *pm_addr, u16 m_alloc_type, u32 num);

/* == constructive functions == */
inline obj_ref_inode_t *ref_inode_create(u64 addr, u32 ino)
{
    obj_ref_inode_t *ref = hk_alloc_obj_ref_inode();
    ref->hdr.ref = 1;
    ref->hdr.addr = addr;
    ref->hdr.ino = ino;
    return ref;
}

inline void ref_inode_destroy(obj_ref_inode_t *ref)
{
    if (ref) {
        hk_free_obj_ref_inode(ref);
    }
}

inline obj_ref_attr_t *ref_attr_create(u64 addr, u32 ino, u16 from_pkg, u64 dep_ofs)
{
    obj_ref_attr_t *ref = hk_alloc_obj_ref_attr();
    ref->hdr.ref = 1;
    ref->hdr.addr = addr;
    ref->hdr.ino = ino;
    ref->from_pkg = from_pkg;
    ref->dep_ofs = dep_ofs;
    return ref;
}

inline void ref_attr_destroy(obj_ref_attr_t *ref)
{
    if (ref) {
        hk_free_obj_ref_attr(ref);
    }
}

inline obj_ref_dentry_t *ref_dentry_create(u64 addr, const char *name, u32 len, u32 ino, u32 parent_ino)
{
    obj_ref_dentry_t *ref = hk_alloc_obj_ref_dentry();
    ref->hdr.addr = addr;
    ref->hdr.ino = parent_ino;
    ref->target_ino = ino;
    ref->hash = BKDRHash(name, len);
    return ref;
}

inline void ref_dentry_destroy(obj_ref_dentry_t *ref)
{
    if (ref) {
        hk_free_obj_ref_dentry(ref);
    }
}

inline obj_ref_data_t *ref_data_create(u64 addr, u32 ino, u64 ofs, u32 num, u64 data_offset)
{
    obj_ref_data_t *ref = hk_alloc_obj_ref_data();
    ref->hdr.ref = 1;
    ref->hdr.addr = addr;
    ref->hdr.ino = ino;
    ref->ofs = ofs;
    ref->num = num;
    ref->data_offset = data_offset;
    ref->type = DATA_REF;
    return ref;
}

inline void ref_data_destroy(obj_ref_data_t *ref)
{
    if (ref) {
        hk_free_obj_ref_data(ref);
    }
}

/* == In-DRAM obj managements == */
int obj_mgr_init(struct hk_sb_info *sbi, u32 cpus, obj_mgr_t *mgr)
{
    int ret = 0, i;

    /* init obj_mgr */
    mgr->num_d_roots = cpus;
    mgr->sbi = sbi;

    rng_lock_init(&mgr->prealloc_imap.rng_lock, cpus, NULL);
    hash_init(mgr->prealloc_imap.map);
    rng_lock_init(&mgr->pending_table.rng_lock, cpus, NULL);
    hash_init(mgr->pending_table.tbl);
    mgr->d_roots = (d_root_t *)kzalloc(sizeof(d_root_t) * cpus, GFP_KERNEL);
    if (!mgr->d_roots) {
        ret = -ENOMEM;
        goto out;
    }
    for (i = 0; i < cpus; i++) {
        hash_init(mgr->d_roots[i].data_obj_refs);
        hash_init(mgr->d_roots[i].dentry_obj_refs);
        spin_lock_init(&mgr->d_roots[i].data_lock);
        spin_lock_init(&mgr->d_roots[i].dentry_lock);
    }

out:
    return ret;
}

void obj_mgr_destroy(obj_mgr_t *mgr)
{
    struct hk_inode_info_header *cur;
    pendlst_t *pendlst;
    claim_req_t *req;
    d_obj_ref_list_t *d_obj_list;
    obj_ref_data_t *ref_data;
    obj_ref_dentry_t *ref_dentry;
    struct list_head *pos, *n;
    d_root_t *root;
    int bkt, root_id;
    struct hlist_node *temp;

    if (mgr) {
        rng_lock_destroy(&mgr->prealloc_imap.rng_lock);
        hash_for_each_safe(mgr->prealloc_imap.map, bkt, temp, cur, hnode)
        {
            hash_del(&cur->hnode);
            if (cur->pack_spec.latest_fop.latest_attr)
                ref_attr_destroy(cur->pack_spec.latest_fop.latest_attr);
            if (cur->pack_spec.latest_fop.latest_inode)
                ref_inode_destroy(cur->pack_spec.latest_fop.latest_inode);
            cur->pack_spec.latest_fop.latest_attr = NULL;
            cur->pack_spec.latest_fop.latest_inode = NULL;
            hk_free_hk_inode_info_header(cur);
        }

        rng_lock_destroy(&mgr->pending_table.rng_lock);
        hash_for_each_safe(mgr->pending_table.tbl, bkt, temp, pendlst, hnode)
        {
            hash_del(&pendlst->hnode);
            list_for_each_safe(pos, n, &pendlst->list)
            {
                req = list_entry(pos, claim_req_t, node);
                list_del(pos);
                hk_free_claim_req(req);
            }
            kfree(pendlst);
        }

        for (root_id = 0; root_id < mgr->num_d_roots; root_id++) {
            root = &mgr->d_roots[root_id];
            /* free ref_data and ref_dentry in d_roots */
            hash_for_each_safe(root->data_obj_refs, bkt, temp, d_obj_list, hnode)
            {
                list_for_each_safe(pos, n, &d_obj_list->list)
                {
                    ref_data = list_entry(pos, obj_ref_data_t, node);
                    list_del(pos);
                    ref_data_destroy(ref_data);
                }
                hash_del(&d_obj_list->hnode);
                kfree(d_obj_list);
            }

            hash_for_each_safe(root->dentry_obj_refs, bkt, temp, d_obj_list, hnode)
            {
                list_for_each_safe(pos, n, &d_obj_list->list)
                {
                    ref_dentry = list_entry(pos, obj_ref_dentry_t, node);
                    list_del(pos);
                    ref_dentry_destroy(ref_dentry);
                }
                hash_del(&d_obj_list->hnode);
                kfree(d_obj_list);
            }
        }

        kfree(mgr->d_roots);
        kfree(mgr);
    }
}

/* lookup data lists for inode. data head could be dentry lists or data block list*/
/* 32 bits ino */
void *hk_lookup_d_obj_ref_lists(d_root_t *root, u32 ino, u8 type)
{
    struct hlist_node *node;
    d_obj_ref_list_t *cur;
    switch (type) {
    case OBJ_DATA:
        hash_for_each_possible(root->data_obj_refs, cur, hnode, ino)
        {
            if (cur->ino == ino) {
                return cur;
            }
        }
        break;
    case OBJ_DENTRY:
        hash_for_each_possible(root->dentry_obj_refs, cur, hnode, ino)
        {
            if (cur->ino == ino) {
                return cur;
            }
        }
        break;
    default:
        break;
    }
    return NULL;
}

int obj_mgr_load_dobj_control(obj_mgr_t *mgr, void *obj_ref, u8 type)
{
    struct hk_layout_info *layout;
    struct hk_sb_info *sbi = mgr->sbi;
    d_obj_ref_list_t *data_list = NULL, *dentry_list = NULL;
    d_root_t *root;
    obj_ref_hdr_t *hdr = (obj_ref_hdr_t *)obj_ref;
    layout = &sbi->layouts[get_layout_idx(sbi, hdr->addr)];

    root = &mgr->d_roots[layout->cpuid];

    switch (type) {
    case OBJ_DATA: {
        use_droot(root, data);
        obj_ref_data_t *ref = (obj_ref_data_t *)obj_ref;
        ref->hdr.ref += 1;
        data_list = hk_lookup_d_obj_ref_lists(root, ref->hdr.ino, OBJ_DATA);
        if (!data_list) {
            data_list = (d_obj_ref_list_t *)kzalloc(sizeof(d_obj_ref_list_t), GFP_ATOMIC);
            data_list->ino = ref->hdr.ino;
            INIT_LIST_HEAD(&data_list->list);
            hash_add(root->data_obj_refs, &data_list->hnode, ref->hdr.ino);
        }
        list_add_tail(&ref->node, &data_list->list);
        rls_droot(root, data);
        break;
    }
    case OBJ_DENTRY: {
        use_droot(root, dentry);
        obj_ref_dentry_t *ref = (obj_ref_dentry_t *)obj_ref;
        ref->hdr.ref += 1;
        dentry_list = hk_lookup_d_obj_ref_lists(root, ref->hdr.ino, OBJ_DENTRY);
        if (!dentry_list) {
            dentry_list = (d_obj_ref_list_t *)kzalloc(sizeof(d_obj_ref_list_t), GFP_ATOMIC);
            dentry_list->ino = ref->hdr.ino;
            INIT_LIST_HEAD(&dentry_list->list);
            hash_add(root->dentry_obj_refs, &dentry_list->hnode, ref->hdr.ino);
        }
        list_add_tail(&ref->node, &dentry_list->list);
        rls_droot(root, dentry);
        break;
    }
    default:
        break;
    }

    return 0;
}

/* obj_ref is held by caller */
int obj_mgr_unload_dobj_control(obj_mgr_t *mgr, void *obj_ref, u8 type)
{
    struct hk_layout_info *layout;
    struct hk_sb_info *sbi = mgr->sbi;
    d_obj_ref_list_t *data_list = NULL, *dentry_list = NULL;
    d_root_t *root;

    layout = &sbi->layouts[get_layout_idx(sbi, ((obj_ref_hdr_t *)obj_ref)->addr)];
    root = &mgr->d_roots[layout->cpuid];

    switch (type) {
    case OBJ_DATA: {
        use_droot(root, data);
        obj_ref_data_t *ref = (obj_ref_data_t *)obj_ref;
        BUG_ON(ref->hdr.ref != 1);
        data_list = hk_lookup_d_obj_ref_lists(root, ref->hdr.ino, OBJ_DATA);
        if (!data_list) {
            BUG_ON(1);
        }
        list_del(&ref->node);
        if (list_empty(&data_list->list)) {
            hash_del(&data_list->hnode);
            kfree(data_list);
        }
        rls_droot(root, data);
        break;
    }
    case OBJ_DENTRY: {
        use_droot(root, dentry);
        obj_ref_dentry_t *ref = (obj_ref_dentry_t *)obj_ref;
        BUG_ON(ref->hdr.ref != 1);
        dentry_list = hk_lookup_d_obj_ref_lists(root, ref->hdr.ino, OBJ_DENTRY);
        if (!dentry_list) {
            BUG_ON(1);
        }
        list_del(&ref->node);
        if (list_empty(&dentry_list->list)) {
            hash_del(&dentry_list->hnode);
            kfree(dentry_list);
        }
        rls_droot(root, dentry);
        break;
    }
    default:
        break;
    }

    return 0;
}

int obj_mgr_get_dobjs(obj_mgr_t *mgr, int cpuid, u32 ino, u8 type, void **obj_refs)
{
    struct hk_sb_info *sbi = mgr->sbi;
    d_obj_ref_list_t *data_list = NULL, *dentry_list = NULL;
    d_root_t *root;

    root = &mgr->d_roots[cpuid];

    *obj_refs = NULL;
    switch (type) {
    case OBJ_DATA: {
        use_droot(root, data);
        data_list = hk_lookup_d_obj_ref_lists(root, ino, OBJ_DATA);
        if (data_list) {
            *obj_refs = data_list;
            rls_droot(root, data);
            return 0;
        }
        rls_droot(root, data);
        break;
    }
    case OBJ_DENTRY: {
        use_droot(root, dentry);
        dentry_list = hk_lookup_d_obj_ref_lists(root, ino, OBJ_DENTRY);
        if (dentry_list) {
            *obj_refs = dentry_list;
            rls_droot(root, dentry);
            return 0;
        }
        rls_droot(root, dentry);
        break;
    }
    default:
        break;
    }

    return -ENOENT;
}

int obj_mgr_load_imap_control(obj_mgr_t *mgr, struct hk_inode_info_header *sih)
{
    int ret = 0;
    imap_t *imap = &mgr->prealloc_imap;
    int slot = hash_min(sih->ino, HASH_BITS(imap->map));

    rng_lock(&imap->rng_lock, slot);
    hlist_add_head(&sih->hnode, &imap->map[slot]);
    rng_unlock(&imap->rng_lock, slot);

    return ret;
}

int obj_mgr_unload_imap_control(obj_mgr_t *mgr, struct hk_inode_info_header *sih)
{
    int ret = 0;
    imap_t *imap = &mgr->prealloc_imap;
    int slot = hash_min(sih->ino, HASH_BITS(imap->map));

    rng_lock(&imap->rng_lock, slot);
    hash_del(&sih->hnode);
    rng_unlock(&imap->rng_lock, slot);

    return ret;
}

struct hk_inode_info_header *obj_mgr_get_imap_inode(obj_mgr_t *mgr, u32 ino)
{
    imap_t *imap = &mgr->prealloc_imap;
    struct hk_inode_info_header *sih;
    int slot = hash_min(ino, HASH_BITS(imap->map));

    rng_lock(&imap->rng_lock, slot);
    hlist_for_each_entry(sih, &imap->map[slot], hnode)
    {
        if (sih->ino == ino) {
            rng_unlock(&imap->rng_lock, slot);
            return sih;
        }
    }
    rng_unlock(&imap->rng_lock, slot);
    return NULL;
}

static claim_req_t *claim_req_create(u64 req_addr, u16 req_type, u16 dep_type, u32 ino)
{
    claim_req_t *req = hk_alloc_claim_req();
    req->req_pkg_addr = req_addr;
    req->req_pkg_type = req_type;
    req->dep_pkg_type = dep_type;
    req->ino = ino;
    return req;
}

static void claim_req_destroy(claim_req_t *req)
{
    if (req) {
        hk_free_claim_req(req);
    }
}

/* For now, only handle UNLINK request */
int obj_mgr_send_claim_request(obj_mgr_t *mgr, u64 dep_pkg_addr, claim_req_t *req)
{
    struct hk_sb_info *sbi = mgr->sbi;
    pendlst_t *pendlst;
    bool found = false;
    int slot = hash_min(dep_pkg_addr, HASH_BITS(mgr->pending_table.tbl));

    hk_dbgv("send req: [Unlink PKG for %lu](req_blk=%llu:%u(B)), [Depend file %lu](dep_blk=%llu:%u(B))\n",
            ((struct hk_pkg_hdr *)(req->req_pkg_addr + OBJ_ATTR_SIZE))->unlink_hdr.unlinked_ino,
            get_pm_blk(sbi, req->req_pkg_addr), req->req_pkg_addr & ~PAGE_MASK,
            ((struct hk_obj_inode *)dep_pkg_addr)->ino,
            get_pm_blk(sbi, dep_pkg_addr), dep_pkg_addr & ~PAGE_MASK);

    rng_lock(&mgr->pending_table.rng_lock, slot);
    hlist_for_each_entry(pendlst, &mgr->pending_table.tbl[slot], hnode)
    {
        if (pendlst->dep_pkg_addr == dep_pkg_addr) {
            found = true;
            break;
        }
    }
    if (!found) {
        pendlst = kmalloc(sizeof(pendlst_t), GFP_ATOMIC);
        if (!pendlst) {
            rng_unlock(&mgr->pending_table.rng_lock, slot);
            return -ENOMEM;
        }
        INIT_LIST_HEAD(&pendlst->list);
    }
    list_add_tail(&req->node, &pendlst->list);
    rng_unlock(&mgr->pending_table.rng_lock, slot);
    return 0;
}

pendlst_t *obj_mgr_get_pendlst(obj_mgr_t *mgr, u64 dep_pkg_addr)
{
    pendlst_t *pendlst;
    struct hk_sb_info *sbi = mgr->sbi;
    int slot = hash_min(dep_pkg_addr, HASH_BITS(mgr->pending_table.tbl));

    rng_lock(&mgr->pending_table.rng_lock, slot);
    hlist_for_each_entry(pendlst, &mgr->pending_table.tbl[slot], hnode)
    {
        if (pendlst->dep_pkg_addr == dep_pkg_addr) {
            hash_del(&pendlst->hnode);
            rng_unlock(&mgr->pending_table.rng_lock, slot);
            return pendlst;
        }
    }
    rng_unlock(&mgr->pending_table.rng_lock, slot);
    return NULL;
}

int obj_mgr_process_claim_request(obj_mgr_t *mgr, u64 dep_pkg_addr)
{
    struct hk_sb_info *sbi = mgr->sbi;
    pendlst_t *pendlst;
    claim_req_t *req;
    struct list_head *pos, *n;
    int ret = 0;
    INIT_TIMING(time);

    HK_START_TIMING(process_claim_req_t, time);
    pendlst = obj_mgr_get_pendlst(mgr, dep_pkg_addr);
    if (pendlst) {
        list_for_each_safe(pos, n, &pendlst->list)
        {
            req = list_entry(pos, claim_req_t, node);
            hk_dbgv("process req: req_blk=%llu (%u), dep_blk=%llu (%u), ino=%d\n", get_pm_blk(sbi, req->req_pkg_addr), req->req_pkg_addr & ~PAGE_MASK, get_pm_blk(sbi, dep_pkg_addr), dep_pkg_addr & ~PAGE_MASK, req->ino);
            ret = do_reclaim_dram_pkg(sbi, mgr, req->req_pkg_addr, req->req_pkg_type);
            if (ret != 0) {
                hk_dbgv("Claim request (0x%lx, 0x%lx) is processed\n", req->req_pkg_addr, dep_pkg_addr);
            }
            list_del(pos);
            claim_req_destroy(req);
        }
        kfree(pendlst);
    }
    HK_END_TIMING(process_claim_req_t, time);

    return 0;
}

static inline int __update_dram_meta(struct hk_inode_info_header *sih, attr_update_t *update)
{
    sih->i_uid = update->i_uid;
    sih->i_gid = update->i_gid;
    sih->i_atime = update->i_atime;
    sih->i_mtime = update->i_mtime;
    sih->i_ctime = update->i_ctime;
    sih->i_links_count = update->i_links_count;
    sih->i_mode = update->i_mode;
    sih->i_size = update->i_size;
    return 0;
}

int do_reclaim_dram_pkg(struct hk_sb_info *sbi, obj_mgr_t *mgr, u64 pkg_addr, u16 pkg_type)
{
    u32 num = 0;
    u64 pkg_ofs = get_pm_offset(sbi, pkg_addr);
    struct hk_layout_info *layout = &sbi->layouts[get_layout_idx(sbi, pkg_ofs)];
    tlfree_param_t param;
    u16 m_alloc_type;
    u64 entrynr;
    u32 blk;
    int ret = 0;

    switch (pkg_type) {
    case PKG_DATA:
        num = MTA_PKG_DATA_BLK;
        m_alloc_type = TL_MTA_PKG_DATA;
        break;
    case PKG_ATTR:
        num = MTA_PKG_ATTR_BLK;
        m_alloc_type = TL_MTA_PKG_ATTR;
        break;
    case PKG_RENAME:
        ret = -EINVAL;
        goto out;
    case PKG_CREATE:
        num = MTA_PKG_CREATE_BLK;
        m_alloc_type = TL_MTA_PKG_CREATE;
        break;
    case PKG_UNLINK:
        num = MTA_PKG_UNLINK_BLK;
        m_alloc_type = TL_MTA_PKG_UNLINK;
        break;
    default:
        break;
    }

    entrynr = GET_ENTRYNR(pkg_ofs);
    blk = GET_ALIGNED_BLKNR(pkg_ofs);
    tl_build_free_param(&param, blk, (entrynr << 32) | num, TL_MTA | m_alloc_type);
    tlfree(&layout->allocator, &param);

    if ((param.freed & TLFREE_BLK) == TLFREE_BLK) {
        hk_clear_bm(sbi, meta_type_to_bmblk(TL_ALLOC_MTA_TYPE(m_alloc_type)), blk);
    }

out:
    return param.freed;
}

/* Called when new attr is emerged */
int reclaim_dram_unlink(obj_mgr_t *mgr, struct hk_inode_info_header *sih)
{
    struct hk_sb_info *sbi = mgr->sbi;
    obj_ref_attr_t *ref_attr = sih->pack_spec.latest_fop.latest_attr;
    struct hk_pkg_hdr *pkg_hdr;
    claim_req_t *req;
    u64 cur_ofs, dep_ofs;
    int ret = 0;

    if (ref_attr == NULL) {
        return -EINVAL;
    }

    cur_ofs = sih->pack_spec.latest_fop.latest_inline_attr;
    dep_ofs = ref_attr->dep_ofs;

    req = claim_req_create(get_pm_addr(sbi, cur_ofs), PKG_UNLINK, PKG_CREATE, sih->ino);
    if (req == NULL) {
        return -ENOMEM;
    }

    ret = obj_mgr_send_claim_request(mgr, get_pm_addr(sbi, dep_ofs), req);
    if (ret) {
        return ret;
    }

    return 0;
}

int reclaim_dram_create(obj_mgr_t *mgr, struct hk_inode_info_header *sih, obj_ref_dentry_t *ref)
{
    struct hk_sb_info *sbi = mgr->sbi;
    u64 pkg_addr = get_pm_addr(sbi, sih->pack_spec.latest_fop.latest_inode->hdr.addr);
    int ret = 0;

    /* reclaim in-DRAM structures */
    ret = obj_mgr_unload_dobj_control(mgr, ref, OBJ_DENTRY);
    if (ret) {
        return ret;
    }

    ret = do_reclaim_dram_pkg(sbi, mgr, pkg_addr, PKG_CREATE);
    if (ret == 0) {
        hk_dbg("%s: reclaim failed\n", __func__);
        return -1;
    }

    return 0;
}

int reclaim_dram_attr(obj_mgr_t *mgr, struct hk_inode_info_header *sih)
{
    struct hk_sb_info *sbi = mgr->sbi;
    struct hk_layout_info *layout;
    obj_ref_attr_t *ref = sih->pack_spec.latest_fop.latest_attr;
    int ret = 0;

    if (ref == NULL) {
        return 0;
    }

    switch (ref->from_pkg) {
    case PKG_ATTR: {
        ret = do_reclaim_dram_pkg(sbi, mgr, get_pm_addr(sbi, ref->hdr.addr), PKG_ATTR);
        if (ret == 0) {
            hk_dbg("latest attr is in another pkg, so do not free it\n");
        }
        break;
    }
    case PKG_UNLINK: {
        if (ref->hdr.addr) {
            ret = do_reclaim_dram_pkg(sbi, mgr, get_pm_addr(sbi, ref->hdr.addr), PKG_ATTR);
            if (ret == 0) {
                hk_dbg("latest attr is in another pkg, so do not free it\n");
            }
        }
        reclaim_dram_unlink(mgr, sih);
        break;
    }
    case PKG_CREATE:
        /* Do not reclaim space */
        break;
    default:
        break;
    }
    /* since we use kmem cache, allocation and free are very fast */
    ref_attr_destroy(ref);
    sih->pack_spec.latest_fop.latest_attr = NULL;
    sih->pack_spec.latest_fop.latest_inline_attr = 0;
    return 0;
}

/* make sure new data is written and persisted */
/* block aligned reclaim */
int reclaim_dram_data(obj_mgr_t *mgr, struct hk_inode_info_header *sih, data_update_t *update)
{
    struct hk_sb_info *sbi = mgr->sbi;
    struct hk_layout_info *layout;
    tlfree_param_t param;
    obj_ref_data_t *ref, *new_ref;
    u32 ofs_blk = GET_ALIGNED_BLKNR(update->ofs);
    u32 old_blk, new_blk = update->blk;
    u32 est_ofs_blk, est_num, blk;
    u32 reclaimed_blks;
    u32 before_remained_blks;
    u32 behind_remained_blks;
    int ret = 0;

    if (update->ofs >= sih->i_size) {
        goto out;
    }

    ref = (obj_ref_data_t *)hk_inode_get_slot(sih, update->ofs);
    if (!ref) {
        /* there's no overlap */
        goto out;
    }

    if (DATA_IS_HOLE(ref->type)) {
        return 0;
    } else if (DATA_IS_REF(ref->type)) {
        est_ofs_blk = GET_ALIGNED_BLKNR(ref->ofs);
        old_blk = GET_ALIGNED_BLKNR(ref->data_offset);
        est_num = ref->num;
        before_remained_blks = ofs_blk - est_ofs_blk;
        behind_remained_blks = est_num < before_remained_blks + update->num ? 0 : est_num - before_remained_blks - update->num;

        hk_dbgv("ino: %lu, est_ofs_blk: %u, est_num: %u, update_blk: %u, update_num: %u, before: %u, behind: %u\n", sih->ino, est_ofs_blk, est_num, ofs_blk, update->num, before_remained_blks, behind_remained_blks);

        if (behind_remained_blks == 0) {
            /* completely overlapped */
            reclaimed_blks = est_num - before_remained_blks;
        } else {
            /* partially overlapped */
            reclaimed_blks = update->num;
        }

        if (behind_remained_blks > 0) {
            u64 length = ((u64)(est_num - behind_remained_blks) << HUNTER_BLK_SHIFT);
            u64 new_data_ofs = ref->data_offset + length;
            u64 new_ofs = ref->ofs + length;
            u64 addr;

            ret = reserve_pkg_space(mgr, &addr, TL_MTA_PKG_DATA, MTA_PKG_DATA_BLK);
            if (ret) {
                return ret;
            }

            new_ref = ref_data_create(get_pm_offset(sbi, addr), sih->ino, new_ofs, behind_remained_blks, new_data_ofs);
            for (blk = 0; blk < behind_remained_blks; blk++) {
                linix_insert(&sih->ix, GET_ALIGNED_BLKNR(new_ofs) + blk, new_ref, false);
            }
            obj_mgr_load_dobj_control(mgr, (void *)new_ref, OBJ_DATA);
        }

        if (before_remained_blks == 0) {
            /* This might be not needed? */
            for (blk = 0; blk < reclaimed_blks; blk++) {
                linix_insert(&sih->ix, est_ofs_blk + blk, NULL, false);
            }
            ref->hdr.ref--;
            obj_mgr_unload_dobj_control(mgr, (void *)ref, OBJ_DATA);
            do_reclaim_dram_pkg(sbi, mgr, get_pm_addr(sbi, ref->hdr.addr), PKG_DATA);
            ref_data_destroy(ref);
        } else {
            ref->num = before_remained_blks;
        }

        /* release data blocks */
        hk_dbgv("ino: %lu, free %u, num %u\n", sih->ino, old_blk + before_remained_blks, reclaimed_blks);
        layout = &sbi->layouts[get_layout_idx(sbi, ((u64)(old_blk + before_remained_blks)) << HUNTER_BLK_SHIFT)];
        tl_build_free_param(&param, old_blk + before_remained_blks, reclaimed_blks, TL_BLK);
        tlfree(&layout->allocator, &param);

        /* note that update->num, before_remained_blks, update->num and est_num */
        /* are all unsigned numbers. Thus we cannot directly subtract them. */
        update->num = before_remained_blks + update->num > est_num ? before_remained_blks + update->num - est_num
                                                                   : 0;
        if (update->num > 0) {
            update->blk = est_ofs_blk + est_num;
            update->ofs = (u64)update->blk << HUNTER_BLK_SHIFT;
            ret = -EAGAIN;
        }
    }

out:
    return ret;
}

int ur_dram_latest_inode(obj_mgr_t *mgr, struct hk_inode_info_header *sih, inode_update_t *update)
{
    u32 ino = update->ino;
    u64 pm_inode = update->addr;
    struct hk_sb_info *sbi = mgr->sbi;

    if (!sih->pack_spec.latest_fop.latest_inode) {
        sih->pack_spec.latest_fop.latest_inode = ref_inode_create(pm_inode, sih->ino);
    } else {
        sih->pack_spec.latest_fop.latest_inode->hdr.addr = pm_inode;
    }
    sih->ino = ino;
    hk_dbgv("create inode %lu, blk %llu (%u)\n", ino, get_pm_blk(sbi, get_pm_addr(sbi, pm_inode)), get_pm_addr(sbi, pm_inode) & ~PAGE_MASK);
    return 0;
}

/* update and reclaim in-DRAM attr, called when rename/create/truncate invoked */
int ur_dram_latest_attr(obj_mgr_t *mgr, struct hk_inode_info_header *sih, attr_update_t *update)
{
    struct hk_sb_info *sbi = mgr->sbi;

    if (!sih->pack_spec.latest_fop.latest_attr) {
        if (update->inline_update) {
            sih->pack_spec.latest_fop.latest_attr = ref_attr_create(0, sih->ino, update->from_pkg, update->dep_ofs);
            sih->pack_spec.latest_fop.latest_inline_attr = update->addr;
        } else {
            sih->pack_spec.latest_fop.latest_attr = ref_attr_create(update->addr, sih->ino, update->from_pkg, update->dep_ofs);
        }
    } else {
        if (update->inline_update) {
            sih->pack_spec.latest_fop.latest_inline_attr = update->addr;
        } else {
            reclaim_dram_attr(mgr, sih);
            sih->pack_spec.latest_fop.latest_attr = ref_attr_create(update->addr, sih->ino, update->from_pkg, update->dep_ofs);
        }
        sih->pack_spec.latest_fop.latest_attr->from_pkg = update->from_pkg;
        sih->pack_spec.latest_fop.latest_attr->dep_ofs = update->dep_ofs;
    }

    hk_dbgv("update dram: attr_blk=%llu (%u), dep_blk=%llu (%u), inline_attr=%llu (%u), ino=%d\n",
            get_pm_blk(sbi, get_pm_addr(sbi, sih->pack_spec.latest_fop.latest_attr->hdr.addr)),
            get_pm_addr(sbi, sih->pack_spec.latest_fop.latest_attr->hdr.addr) & ~PAGE_MASK,
            get_pm_blk(sbi, get_pm_addr(sbi, update->dep_ofs)),
            get_pm_addr(sbi, update->dep_ofs) & ~PAGE_MASK,
            get_pm_blk(sbi, get_pm_addr(sbi, sih->pack_spec.latest_fop.latest_inline_attr)),
            get_pm_addr(sbi, sih->pack_spec.latest_fop.latest_inline_attr) & ~PAGE_MASK,
            sih->ino);

    __update_dram_meta(sih, update);

    return 0;
}

/* update and reclaim in-DRAM data, called when rename/create/truncate invoked */
int ur_dram_data(obj_mgr_t *mgr, struct hk_inode_info_header *sih, data_update_t *update)
{
    struct hk_sb_info *sbi = mgr->sbi;
    obj_ref_data_t *ref;
    u32 ofs_blk = GET_ALIGNED_BLKNR(update->ofs);
    u32 num = update->num;
    int ret, i;
    INIT_TIMING(time);

    HK_START_TIMING(data_claim_t, time);
    if (!update->build_from_exist) {
        /* handle data to obj mgr */
        ref = ref_data_create(update->addr, sih->ino, update->ofs, update->num, get_pm_blk_offset(sbi, update->blk));
        obj_mgr_load_dobj_control(mgr, (void *)ref, OBJ_DATA);
    } else {
        ref = (obj_ref_data_t *)update->exist_ref;
    }

    /* handle overlap */
    while (reclaim_dram_data(mgr, sih, update) == -EAGAIN) {
        ;
    }

    /* update dram attr */
    sih->i_ctime = sih->i_mtime = update->i_cmtime;
    sih->i_atime = update->i_cmtime;
    sih->i_size = update->i_size;

    /* make data visible to user */
    for (i = 0; i < num; i++) {
        linix_insert(&sih->ix, ofs_blk + i, ref, true);
    }

    HK_END_TIMING(data_claim_t, time);
    return 0;
}

/* == In-PM pkg managements == */
int reserve_pkg_space_in_layout(obj_mgr_t *mgr, struct hk_layout_info *layout, u64 *pm_addr, u32 num, u16 m_alloc_type)
{
    struct hk_sb_info *sbi = mgr->sbi;
    tl_allocator_t *alloc = &layout->allocator;
    tlalloc_param_t param;
    unsigned long addr, entrynr;
    s32 ret = 0;
    INIT_TIMING(time);

    HK_START_TIMING(reserve_pkg_in_layout_t, time);
    tl_build_alloc_param(&param, num, TL_MTA | m_alloc_type);
    ret = tlalloc(alloc, &param);
    if (ret) {
        hk_dbgv("%s failed %d\n", __func__, ret);
        goto out;
    }
    
    if (param._ret_allocated > 0) {
        /* ensure meta block be written synchronously, for fast recovery */
        /* let's see the penalty of this */
        /* During sequential write, this can be ignored */
        /* However, random write can suffer severe due to this */
        hk_set_bm(sbi, meta_type_to_bmblk(TL_ALLOC_MTA_TYPE(m_alloc_type)), param._ret_rng.low);
    }

    addr = param._ret_rng.low;
    entrynr = param._ret_rng.high;

    *pm_addr = get_pm_entry_addr(sbi, addr, entrynr);

out:
    HK_END_TIMING(reserve_pkg_in_layout_t, time);
    return ret;
}

static int reserve_pkg_space(obj_mgr_t *mgr, u64 *pm_addr, u16 m_alloc_type, u32 num)
{
    struct hk_sb_info *sbi = mgr->sbi;
    struct super_block *sb = sbi->sb;
    struct hk_layout_info *layout;
    u32 start_cpuid, cpuid, i;
    bool found = false;
    int ret = 0;
    INIT_TIMING(time);

    HK_START_TIMING(reserve_pkg_t, time);

    start_cpuid = hk_get_cpuid(sb);
    for (i = 0; i < sbi->num_layout; i++) {
        cpuid = (start_cpuid + i) % sbi->num_layout;
        layout = &sbi->layouts[cpuid];
        if (reserve_pkg_space_in_layout(mgr, layout, pm_addr, num, m_alloc_type) == 0) {
            found = true;
            break;
        }
    }

    if (!found) {
        hk_dbg("%s failed to reserve pkg space", __func__);
        ret = -ENOSPC;
    }

    HK_END_TIMING(reserve_pkg_t, time);
    return ret;
}

/* == Transactional file operations/IO managements == */
static void __always_inline __fill_pm_obj_hdr(struct hk_sb_info *sbi, struct hk_obj_hdr *hdr, u32 type)
{
    hdr->magic = HUNTER_OBJ_MAGIC;
    hdr->type = type;
    hdr->vtail = hk_inc_and_get_vtail(sbi);
    hdr->crc32 = 0;
    hdr->reserved = 0;
}

typedef struct fill_param {
    u32 ino;
    void *data;
} fill_param_t;

void __fill_pm_inode(struct hk_sb_info *sbi, struct hk_obj_inode *pm_inode, u32 ino, u32 rdev, inode_update_t *update)
{
    pm_inode->ino = ino;
    pm_inode->i_create_time = 0;
    pm_inode->i_flags = 0;
    pm_inode->i_xattr = 0;
    pm_inode->i_generation = 0;
    pm_inode->dev.rdev = rdev;
    update->addr = get_pm_offset(sbi, pm_inode);
    update->ino = ino;
    __fill_pm_obj_hdr(sbi, &pm_inode->hdr, OBJ_INODE);
}

void __fill_pm_inode_from_exist(struct hk_sb_info *sbi, struct hk_obj_inode *pm_inode, inode_update_t *update)
{
    struct super_block *sb = sbi->sb;
    struct hk_inode_info_header *sih = update->sih;
    BUG_ON(sih->si == NULL);
    struct inode *inode = &sih->si->vfs_inode;
    unsigned long irq_flags = 0;

    hk_memunlock_range(sb, pm_inode, sizeof(struct hk_obj_inode), &irq_flags);
    pm_inode->ino = sih->ino;
    pm_inode->i_create_time = inode->i_ctime.tv_sec;
    pm_inode->i_flags = inode->i_flags;
    pm_inode->i_xattr = 0;
    pm_inode->i_generation = inode->i_generation;
    pm_inode->dev.rdev = inode->i_rdev;
    update->addr = get_pm_offset(sbi, pm_inode);
    update->ino = sih->ino;
    __fill_pm_obj_hdr(sbi, &pm_inode->hdr, OBJ_INODE);
    hk_memlock_range(sb, pm_inode, sizeof(struct hk_obj_inode), &irq_flags);
}

typedef struct fill_attr {
    u16 mode;
    u16 options;
    int size_change;
    int link_change;
    u32 time;
    u32 uid;
    u32 gid;
    void *inherit;
    attr_update_t *update; /* pass out dram updates */
} fill_attr_t;

/* used only by internal fill pm */
#define FILL_ATTR_INIT                    0x0000
#define FILL_ATTR_EXIST                   0x0001
#define FILL_ATTR_TYPE_MASK               0x000F
#define FILL_ATTR_TYPE(options)           (options & FILL_ATTR_TYPE_MASK)
#define FILL_ATTR_INHERIT                 0x8000
#define FILL_ATTR_LINK_CHANGE             0x4000
#define FILL_ATTR_SIZE_CHANGE             0x2000
#define FILL_ATTR_ACTION_MASK             0xFFF0
#define IS_FILL_ATTR_INHERIT(options)     (options & FILL_ATTR_INHERIT)
#define IS_FILL_ATTR_LINK_CHANGE(options) (options & FILL_ATTR_LINK_CHANGE)
#define IS_FILL_ATTR_SIZE_CHANGE(options) (options & FILL_ATTR_SIZE_CHANGE)

void __fill_pm_attr(struct hk_sb_info *sbi, struct hk_obj_attr *attr, fill_param_t *param)
{
    struct super_block *sb = sbi->sb;
    unsigned long flags = 0;
    u32 ino = param->ino;
    fill_attr_t *attr_param = (fill_attr_t *)param->data;
    u16 mode = attr_param->mode;
    u16 options = attr_param->options;
    u32 i_atime, i_ctime, i_mtime;
    u64 i_size;
    u32 i_uid, i_gid;
    u16 i_links_count;
    u16 i_mode;

    if (FILL_ATTR_TYPE(options) == FILL_ATTR_INIT) {
        if (S_ISDIR(mode)) {
            i_mode = S_IFDIR | mode;
        } else if (S_ISREG(mode)) {
            i_mode = S_IFREG | mode;
        } else {
            i_mode = mode;
        }
        i_mtime = i_ctime = i_atime = attr_param->time;
        i_size = 0;
        i_uid = attr_param->uid;
        i_gid = attr_param->gid;
        i_links_count = 1;
    } else if (FILL_ATTR_TYPE(options) == FILL_ATTR_EXIST) {
        struct hk_inode_info_header *sih = (struct hk_inode_info_header *)attr_param->inherit;

        i_mode = sih->i_mode;
        i_atime = sih->i_atime;
        i_ctime = sih->i_ctime;
        i_mtime = sih->i_mtime;
        i_uid = sih->i_uid;
        i_gid = sih->i_gid;
        if (IS_FILL_ATTR_INHERIT(options)) {
            i_links_count = sih->i_links_count;
            i_size = sih->i_size;
        }
        if (IS_FILL_ATTR_SIZE_CHANGE(options)) {
            i_size = sih->i_size + attr_param->size_change;
        }
        if (IS_FILL_ATTR_LINK_CHANGE(options)) {
            i_links_count = sih->i_links_count + attr_param->link_change;
        }
    }

    if (attr_param->update) {
        attr_param->update->ino = ino;
        attr_param->update->i_mode = i_mode;
        attr_param->update->i_atime = i_atime;
        attr_param->update->i_ctime = i_ctime;
        attr_param->update->i_mtime = i_mtime;
        attr_param->update->i_size = i_size;
        attr_param->update->i_uid = i_uid;
        attr_param->update->i_gid = i_gid;
        attr_param->update->i_links_count = i_links_count;
        if (attr != NULL)
            attr_param->update->addr = get_pm_offset(sbi, attr);
        else
            attr_param->update->addr = 0; /* we need to assign out side */
        attr_param->update->from_pkg = PKG_CREATE;
        attr_param->update->dep_ofs = 0;
        attr_param->update->inline_update = false;
    }

    if (attr != NULL) {
        hk_memunlock_range(sb, attr, sizeof(struct hk_obj_attr), &flags);
        attr->ino = ino;
        attr->i_mode = i_mode;
        attr->i_atime = i_atime;
        attr->i_ctime = i_ctime;
        attr->i_mtime = i_mtime;
        attr->i_size = i_size;
        attr->i_uid = i_uid;
        attr->i_gid = i_gid;
        attr->i_links_count = i_links_count;
        __fill_pm_obj_hdr(sbi, &attr->hdr, OBJ_ATTR);
        hk_memlock_range(sb, attr, sizeof(struct hk_obj_attr), &flags);
    }
}

typedef struct fill_dentry {
    u32 parent_ino;
    char *name;
    u32 len;
} fill_dentry_t;

void __fill_pm_dentry(struct hk_sb_info *sbi, struct hk_obj_dentry *dentry, fill_param_t *param)
{
    struct super_block *sb = sbi->sb;
    fill_dentry_t *dentry_param = (fill_dentry_t *)param->data;
    unsigned long flags = 0;

    dentry->ino = param->ino;
    dentry->parent_ino = dentry_param->parent_ino;

    hk_memunlock_range(sb, dentry, sizeof(struct hk_obj_dentry), &flags);
    memcpy(dentry->name, dentry_param->name, dentry_param->len);
    dentry->name[dentry_param->len] = '\0';
    __fill_pm_obj_hdr(sbi, &dentry->hdr, OBJ_DENTRY);
    hk_memlock_range(sb, dentry, sizeof(struct hk_obj_dentry), &flags);
}

typedef struct fill_pkg_hdr {
    u16 type;      /* this package type */
    u64 link_addr; /* guarantee atomicity for bin, point to another pkg */
    union {
        struct {
            struct hk_inode_info_header *sih;
            struct hk_inode_info_header *psih;
        } fill_create_hdr;
        /* for unlink operations */
        struct {
            struct hk_inode_info_header *psih;
            u32 unlinked_ino;
            u64 dep_ofs;
        } fill_unlink_hdr;
    };
} fill_pkg_hdr_t;

void __assign_create_pkg_hdr_param(struct hk_sb_info *sbi, fill_pkg_hdr_t *pkg_hdr_param, struct hk_pkg_hdr *pkg_hdr)
{
    if (pkg_hdr_param->fill_create_hdr.psih) {
        pkg_hdr->create_hdr.parent_attr.i_size = pkg_hdr_param->fill_create_hdr.psih->i_size + OBJ_DENTRY;
        pkg_hdr->create_hdr.parent_attr.i_links_count = pkg_hdr_param->fill_create_hdr.psih->i_links_count + 1;
        pkg_hdr->create_hdr.parent_attr.i_cmtime = pkg_hdr_param->fill_create_hdr.psih->i_ctime;

        pkg_hdr->create_hdr.attr.ino = pkg_hdr_param->fill_create_hdr.psih->ino;
    }
    BUG_ON(!pkg_hdr_param->fill_create_hdr.sih);
    pkg_hdr->create_hdr.attr.i_mode = pkg_hdr_param->fill_create_hdr.sih->i_mode;
    pkg_hdr->create_hdr.attr.i_uid = pkg_hdr_param->fill_create_hdr.sih->i_uid;
    pkg_hdr->create_hdr.attr.i_gid = pkg_hdr_param->fill_create_hdr.sih->i_gid;
}

void __assign_unlink_pkg_hdr_param(struct hk_sb_info *sbi, fill_pkg_hdr_t *pkg_hdr_param, struct hk_pkg_hdr *pkg_hdr)
{
    BUG_ON(!pkg_hdr_param->fill_unlink_hdr.psih);
    pkg_hdr->unlink_hdr.unlinked_ino = pkg_hdr_param->fill_unlink_hdr.unlinked_ino;
    pkg_hdr->unlink_hdr.dep_ofs = pkg_hdr_param->fill_unlink_hdr.dep_ofs;
    pkg_hdr->unlink_hdr.parent_attr.ino = pkg_hdr_param->fill_unlink_hdr.psih->ino;
    pkg_hdr->unlink_hdr.parent_attr.i_size = pkg_hdr_param->fill_unlink_hdr.psih->i_size - OBJ_DENTRY_SIZE;
    pkg_hdr->unlink_hdr.parent_attr.i_links_count = pkg_hdr_param->fill_unlink_hdr.psih->i_links_count - 1;
    pkg_hdr->unlink_hdr.parent_attr.i_cmtime = pkg_hdr_param->fill_unlink_hdr.psih->i_ctime;
}

void __fill_pm_pkg_hdr(struct hk_sb_info *sbi, struct hk_pkg_hdr *pkg_hdr, fill_param_t *param)
{
    fill_pkg_hdr_t *pkg_hdr_param = (fill_pkg_hdr_t *)param->data;
    struct super_block *sb = sbi->sb;
    unsigned long flags = 0;

    hk_memunlock_range(sb, pkg_hdr, sizeof(struct hk_pkg_hdr), &flags);
    pkg_hdr->pkg_type = pkg_hdr_param->type;
    switch (pkg_hdr_param->type) {
    case PKG_DATA:
    case PKG_ATTR:
        break;
    case PKG_CREATE:
        __assign_create_pkg_hdr_param(sbi, pkg_hdr_param, pkg_hdr);
        break;
    case PKG_UNLINK:
        __assign_unlink_pkg_hdr_param(sbi, pkg_hdr_param, pkg_hdr);
        break;
    case PKG_RENAME:
        __assign_unlink_pkg_hdr_param(sbi, pkg_hdr_param, pkg_hdr);
        pkg_hdr->hdr.reserved = get_pm_offset(sbi, pkg_hdr_param->link_addr);
        break;
    default:
        break;
    }
    __fill_pm_obj_hdr(sbi, &pkg_hdr->hdr, OBJ_PKGHDR);
    hk_memlock_range(sb, pkg_hdr, sizeof(struct hk_pkg_hdr), &flags);
}

/* TODO: obj_start should be in-DRAM address */
void commit_pkg(struct hk_sb_info *sbi, void *obj_start, u32 len, struct hk_obj_hdr *last_obj_hdr)
{
    struct super_block *sb = sbi->sb;
    unsigned long flags = 0;
    INIT_TIMING(time);

    HK_START_TIMING(wr_once_t, time);
    hk_memunlock_range(sb, last_obj_hdr, sizeof(struct hk_obj_hdr), &flags);
    /* fence-once */
    last_obj_hdr->crc32 = hk_crc32c(~0, (const char *)obj_start, len);
    hk_flush_buffer(obj_start, len, true);
    hk_memlock_range(sb, last_obj_hdr, sizeof(struct hk_obj_hdr), &flags);
    HK_END_TIMING(wr_once_t, time);
}

int check_pkg_valid(void *obj_start, u32 len, struct hk_obj_hdr *last_obj_hdr)
{
    u32 crc32 = last_obj_hdr->crc32;
    last_obj_hdr->crc32 = 0;
    int valid = 1;

    if (!(hk_crc32c(~0, (const char *)obj_start, len) == crc32)) {
        valid = 0;
    }
    last_obj_hdr->crc32 = crc32;

    return valid;
}

/* create in-pm packages and reclaim in-dram attr */
/* inode should be passed in without initialization if create_for_rename == false (wrapped in in_param) */
/* inode should be passed in with initialization if create_for_rename == true (wrapped in in_param) */
int create_new_inode_pkg(struct hk_sb_info *sbi, u16 mode, const char *name,
                         struct hk_inode_info_header *sih, struct hk_inode_info_header *psih,
                         in_pkg_param_t *in_param, out_pkg_param_t *out_param)
{
    u64 cur_addr;
    inode_mgr_t *inode_mgr = sbi->inode_mgr;
    obj_mgr_t *obj_mgr = sbi->pack_layout.obj_mgr;
    struct hk_obj_attr *attr, *pattr;
    struct hk_obj_dentry *obj_dentry;
    struct hk_obj_inode *obj_inode;
    struct hk_pkg_hdr *pkg_hdr;
    obj_ref_dentry_t *ref_dentry;
    fill_param_t fill_param;
    inode_update_t inode_update;
    attr_update_t attr_update, pattr_update;
    int create_type = ((in_create_pkg_param_t *)(in_param->private))->create_type;
    u32 rdev = ((in_create_pkg_param_t *)(in_param->private))->rdev;
    u32 ino, parent_ino, orig_ino;
    int ret = 0;
    unsigned char pkg_buf[MTA_PKG_CREATE_SIZE];
    INIT_TIMING(time);

    HK_START_TIMING(new_inode_trans_t, time);

    if (strlen(name) > HK_NAME_LEN) {
        return -ENAMETOOLONG;
    }

    switch (create_type) {
    case CREATE_FOR_RENAME:
        ino = sih->ino;
        break;
    case CREATE_FOR_LINK:
        orig_ino = ((in_create_pkg_param_t *)(in_param->private))->old_ino;
        /* fall thru */
    case CREATE_FOR_SYMLINK:
    case CREATE_FOR_NORMAL:
        ino = ((in_create_pkg_param_t *)(in_param->private))->new_ino;
        break;
    default:
        break;
    }

    if (in_param->cur_pkg_addr != 0) {
        out_param->addr = in_param->cur_pkg_addr;
    } else {
        ret = reserve_pkg_space(obj_mgr, &out_param->addr, TL_MTA_PKG_CREATE, MTA_PKG_CREATE_BLK);
        if (ret) {
            goto out;
        }
    }

    fill_attr_t attr_param;
    // cur_addr = out_param->addr;
    cur_addr = pkg_buf;
    if (create_type == CREATE_FOR_RENAME) {
        hk_dbgv("create inode pkg, ino: %u, addr: 0x%llx, offset: 0x%llx\n", ino, out_param->addr, get_pm_offset(sbi, out_param->addr));
        /* fill inode from existing inode */
        obj_inode = (struct hk_obj_inode *)cur_addr;
        inode_update.sih = sih;
        __fill_pm_inode_from_exist(sbi, obj_inode, &inode_update);
        inode_update.addr = get_pm_offset(sbi, out_param->addr);
        cur_addr += OBJ_INODE_SIZE;
    } else {
        if (create_type == CREATE_FOR_LINK)
            hk_dbgv("create new inode pkg, ino: %u (-> %u), addr: 0x%llx, offset: 0x%llx\n", ino, orig_ino, out_param->addr, get_pm_offset(sbi, out_param->addr));
        else if (create_type == CREATE_FOR_SYMLINK)
            hk_dbgv("create new inode pkg, ino: %u (symdata @ 0x%llx), addr: 0x%llx, offset: 0x%llx\n", ino, in_param->next_pkg_addr, out_param->addr, get_pm_offset(sbi, out_param->addr));
        else
            hk_dbgv("create new inode pkg, ino: %u, addr: 0x%llx, offset: 0x%llx\n", ino, out_param->addr, get_pm_offset(sbi, out_param->addr));
        /* fill inode */
        obj_inode = (struct hk_obj_inode *)cur_addr;
        __fill_pm_inode(sbi, obj_inode, ino, rdev, &inode_update);
        inode_update.addr = get_pm_offset(sbi, out_param->addr);
        cur_addr += OBJ_INODE_SIZE;
    }

    /* fill dentry */
    parent_ino = psih ? psih->ino : 0;
    fill_dentry_t dentry_param = {
        .parent_ino = parent_ino,
        .name = name,
        .len = strlen(name)};
    obj_dentry = (struct hk_obj_dentry *)cur_addr;
    fill_param.data = &dentry_param;
    __fill_pm_dentry(sbi, obj_dentry, &fill_param);
    cur_addr += OBJ_DENTRY_SIZE;

    /* fill pkg hdr */
    fill_pkg_hdr_t pkg_hdr_param;
    pkg_hdr = (struct hk_pkg_hdr *)cur_addr;
    if (in_param->bin) {
        pkg_hdr_param.type = in_param->bin_type;
        pkg_hdr_param.link_addr = in_param->next_pkg_addr;
    } else {
        pkg_hdr_param.type = PKG_CREATE;
    }
    pkg_hdr_param.fill_create_hdr.psih = psih;
    pkg_hdr_param.fill_create_hdr.sih = sih;
    fill_param.data = &pkg_hdr_param;
    __fill_pm_pkg_hdr(sbi, pkg_hdr, &fill_param);

    cur_addr += OBJ_PKGHDR_SIZE;

    /* flush + fence-once to commit the package */
    // commit_pkg(sbi, (void *)(out_param->addr), cur_addr - out_param->addr, &pkg_hdr->hdr);
    unsigned long flags = 0;
    pkg_hdr->hdr.crc32 = hk_crc32c(~0, (const char *)pkg_buf, MTA_PKG_CREATE_SIZE);
    hk_memunlock_range(sbi->sb, (void *)out_param->addr, MTA_PKG_CREATE_SIZE, &flags);
    /* fence-once */
    memcpy_to_pmem_nocache((void *)out_param->addr, pkg_buf, MTA_PKG_CREATE_SIZE);
    hk_memlock_range(sbi->sb, (void *)out_param->addr, MTA_PKG_CREATE_SIZE, &flags);

    /* address re-assignment */
    obj_dentry = (struct hk_obj_dentry *)(out_param->addr + OBJ_INODE_SIZE);
    pkg_hdr = (struct hk_pkg_hdr *)(out_param->addr + OBJ_INODE_SIZE + OBJ_DENTRY_SIZE);

    /* Now, we can update DRAM structures  */
    if (create_type == CREATE_FOR_RENAME) {
        /* fill pseudo attr in DRAM for further update, but do not allocate in PM */
        attr_param.mode = mode;
        attr_param.time = sih->i_ctime;
        attr_param.gid = sih->i_gid;
        attr_param.uid = sih->i_uid;
        attr_param.options = FILL_ATTR_EXIST | FILL_ATTR_INHERIT;
        attr_param.inherit = sih;
        attr_param.update = &attr_update;

        fill_param.ino = ino;
        fill_param.data = &attr_param;
        __fill_pm_attr(sbi, NULL, &fill_param);
    } else {
        /* fill pseudo attr in DRAM for further update, but do not allocate in PM */
        attr_param.mode = mode;
        attr_param.time = sih->i_ctime;
        attr_param.gid = sih->i_gid;
        attr_param.uid = sih->i_uid;
        attr_param.options = FILL_ATTR_INIT;
        attr_param.inherit = NULL;
        attr_param.update = &attr_update;

        if (create_type == CREATE_FOR_LINK)
            fill_param.ino = orig_ino;
        else
            fill_param.ino = ino;

        fill_param.data = &attr_param;
        __fill_pm_attr(sbi, NULL, &fill_param);
    }

    /* fill pseudo parent attr in DRAM for further update, but do not allocate in PM */
    /* if it is root inode, there is no parent inode */
    if (psih) {
        attr_param.options = FILL_ATTR_EXIST | (FILL_ATTR_LINK_CHANGE | FILL_ATTR_SIZE_CHANGE);
        attr_param.link_change = 1;
        attr_param.size_change = OBJ_DENTRY_SIZE;
        attr_param.inherit = psih;
        attr_param.update = &pattr_update;
        fill_param.data = &attr_param;
        __fill_pm_attr(sbi, NULL, &fill_param);
    }

    /* update attr_update/pattr_update addr */
    attr_update.addr = get_pm_offset(sbi, pkg_hdr);
    attr_update.inline_update = true;
    pattr_update.addr = get_pm_offset(sbi, pkg_hdr);
    pattr_update.inline_update = true;

    /* handle dram updates */
    ur_dram_latest_inode(obj_mgr, sih, &inode_update);
    ur_dram_latest_attr(obj_mgr, sih, &attr_update);
    if (psih) {
        ur_dram_latest_attr(obj_mgr, psih, &pattr_update);
    }

    if (create_type == CREATE_FOR_LINK) {
        ref_dentry = ref_dentry_create(get_pm_offset(sbi, (u64)obj_dentry), name, strlen(name), orig_ino, parent_ino);
    } else {
        /* handle dentry to obj mgr  */
        ref_dentry = ref_dentry_create(get_pm_offset(sbi, (u64)obj_dentry), name, strlen(name), ino, parent_ino);
    }
    obj_mgr_load_dobj_control(obj_mgr, (void *)ref_dentry, OBJ_DENTRY);
    ((out_create_pkg_param_t *)out_param->private)->ref = ref_dentry;

    /* load inode into imap */
    obj_mgr_load_imap_control(obj_mgr, sih);

    /* check if the pkg addr is dependent by UNLINK. If so, reclaim that unlink */
    /* The thing is that if we've unlink one inode, and this UNLINK cannot be reclaimed directly */
    /* until its corresponding CREATE is reclaimed.  */
    ret = obj_mgr_process_claim_request(obj_mgr, out_param->addr);

out:
    HK_END_TIMING(new_inode_trans_t, time);
    return ret;
}

/* remove dentry in pfi first. Then hold dentry's ref to process unlink pkg creation */
/* note: drop fi's latest fop outside */
int create_unlink_pkg(struct hk_sb_info *sbi, struct hk_inode_info_header *sih,
                      struct hk_inode_info_header *psih, obj_ref_dentry_t *ref,
                      in_pkg_param_t *in_param, out_pkg_param_t *out_param)
{
    obj_mgr_t *obj_mgr = sbi->pack_layout.obj_mgr;
    inode_mgr_t *inode_mgr = sbi->inode_mgr;
    struct hk_obj_attr *pattr;
    attr_update_t pattr_update;
    fill_param_t fill_param;
    u64 cur_addr;
    u64 dep_ofs;
    int ret;
    INIT_TIMING(time);

    HK_START_TIMING(new_unlink_trans_t, time);

    if (in_param->cur_pkg_addr != 0) {
        out_param->addr = in_param->cur_pkg_addr;
    } else {
        ret = reserve_pkg_space(obj_mgr, &out_param->addr, TL_MTA_PKG_UNLINK, MTA_PKG_UNLINK_BLK);
        if (ret) {
            goto out;
        }
    }

    cur_addr = out_param->addr;
    dep_ofs = sih->pack_spec.latest_fop.latest_inode->hdr.addr;

    /* fill pkg hdr */
    fill_pkg_hdr_t pkg_hdr_param;
    struct hk_pkg_hdr *pkg_hdr = (struct hk_pkg_hdr *)cur_addr;
    if (in_param->bin) {
        pkg_hdr_param.type = HK_BIN_TO_PKG_TYPE(in_param->bin_type);
        pkg_hdr_param.link_addr = in_param->next_pkg_addr;
    } else {
        pkg_hdr_param.type = PKG_UNLINK;
    }
    pkg_hdr_param.fill_unlink_hdr.psih = psih;
    pkg_hdr_param.fill_unlink_hdr.dep_ofs = dep_ofs;
    pkg_hdr_param.fill_unlink_hdr.unlinked_ino = sih->ino;
    fill_param.data = &pkg_hdr_param;
    __fill_pm_pkg_hdr(sbi, pkg_hdr, &fill_param);
    cur_addr += OBJ_PKGHDR_SIZE;

    /* flush + fence-once to commit the package */
    commit_pkg(sbi, (void *)(out_param->addr), cur_addr - out_param->addr, &pkg_hdr->hdr);

    /* fill pseudo parent attr to prevent in-PM allocation */
    fill_attr_t attr_param = {
        .options = FILL_ATTR_EXIST | (FILL_ATTR_SIZE_CHANGE | FILL_ATTR_LINK_CHANGE),
        .inherit = psih,
        .update = &pattr_update,
    };
    attr_param.link_change = -1;
    attr_param.size_change = -OBJ_DENTRY_SIZE;
    fill_param.ino = psih->ino;
    fill_param.data = &attr_param;
    __fill_pm_attr(sbi, NULL, &fill_param);

    /* handle dram updates */
    pattr_update.from_pkg = PKG_UNLINK;
    /* we cannot remove unlink till we release the space of target's CREATE PKG */
    pattr_update.dep_ofs = dep_ofs;
    pattr_update.inline_update = true;
    ur_dram_latest_attr(obj_mgr, psih, &pattr_update);

    /* remove existing create pkg */
    reclaim_dram_create(obj_mgr, sih, ref);

    /* unload inode from imap when evict inode */
out:
    HK_END_TIMING(new_unlink_trans_t, time);
    return ret;
}

/* Not, only support update size now */
int update_data_pkg(struct hk_sb_info *sbi, struct hk_inode_info_header *sih,
                    u64 hdr_addr, u64 num_kv_pairs, ...)
{
    int i, ret = 0;
    va_list ap;
    struct hk_obj_data *data = (struct hk_obj_data *)hdr_addr;
    size_t new_size = sih->i_size;

    va_start(ap, (num_kv_pairs << 1));
    for (i = 0; i < num_kv_pairs << 1; i += 2) {
        u64 key = va_arg(ap, u64);
        u64 value = va_arg(ap, u64);
        switch (key) {
        case UPDATE_SIZE_FOR_APPEND:
            new_size = value;
            /* To avoid re-calc CheckSum, we store the value in the reserved area */
            /* NOTE: To recover, first assign `reserved` to 0, and see if the pack */
            /*       is valid. If valid, then this is a good package. Otherwise it */
            /*       can be discarded.*/
            data->hdr.reserved = value;
            hk_flush_buffer(data, CACHELINE_SIZE, true);
            break;
        default:
            ret = -EINVAL;
            break;
        }
    }
    va_end(ap);

    sih->i_size = new_size;

    return ret;
}

/* create data pkg for a new inode, `data_addr`: in-pm addr, `offset`: in-file offset, `size`: written data size */
int create_data_pkg(struct hk_sb_info *sbi, struct hk_inode_info_header *sih,
                    u64 data_addr, off_t offset, size_t size, u64 num,
                    in_pkg_param_t *in_param, out_pkg_param_t *out_param)
{
    obj_mgr_t *obj_mgr = sbi->pack_layout.obj_mgr;
    struct hk_obj_data *data;
    struct hk_inode_info *si;
    data_update_t data_update;
    size_t aligned_size = _round_up(size, HK_LBLK_SZ(sbi));
    size_t size_after_write = offset + size > sih->i_size ? offset + size : sih->i_size;
    u64 blk = 0;
    int ret = 0;
    u32 num_meta_blk = MTA_PKG_DATA_BLK;
    INIT_TIMING(time);

    HK_START_TIMING(new_data_trans_t, time);
    blk = get_pm_blk(sbi, data_addr);

    // if (sbi->aging_pos > AGING_PHASE_2) {
    //     if (sbi->aging_pos - 512 * 4096 < AGING_PHASE_2) {
    //         hk_info("aging phase 2, half meta locality\n");
    //     }
    //     num_meta_blk = 128 >> HUNTER_MTA_SHIFT;
    // }

    // if (sbi->aging_pos > AGING_PHASE_3) {
    //     if (sbi->aging_pos - 512 * 4096 < AGING_PHASE_3) {
    //         hk_info("aging phase 4, no meta locality\n");
    //     }
    //     num_meta_blk = 256 >> HUNTER_MTA_SHIFT;
    // }

    num_meta_blk = genrand_int32() % 4 + 1;

    ret = reserve_pkg_space(obj_mgr, &out_param->addr, TL_MTA_PKG_DATA, num_meta_blk);
    if (ret) {
        goto out;
    }

    data = (struct hk_obj_data *)(out_param->addr);

    data->ino = sih->ino;
    data->blk = blk;
    data->ofs = offset;
    data->num = num;
    data->i_cmtime = sih->i_ctime;
    data->i_size = size_after_write;
    if (in_param->bin) {
        __fill_pm_obj_hdr(sbi, &data->hdr, ((u32)in_param->bin_type << 16) | OBJ_DATA);
    } else {
        __fill_pm_obj_hdr(sbi, &data->hdr, OBJ_DATA);
    }

    if (unlikely(size < HK_LBLK_SZ(sbi))) {
        PERSISTENT_BARRIER();
    }
    /* flush + fence-once to commit the package */
    commit_pkg(sbi, (void *)(out_param->addr), OBJ_DATA_SIZE, &data->hdr);

    /* NOTE: prevent read after persist  */
    data_update.build_from_exist = false;
    data_update.exist_ref = NULL;
    data_update.addr = get_pm_offset(sbi, data);
    data_update.blk = blk;
    data_update.ofs = offset;
    data_update.num = num;
    data_update.i_cmtime = sih->i_ctime;
    data_update.i_size = size_after_write;

    ur_dram_data(obj_mgr, sih, &data_update);

out:
    HK_END_TIMING(new_data_trans_t, time);
    return ret;
}

/* this would change in dram structure, so just call it  */
int create_attr_pkg(struct hk_sb_info *sbi, struct hk_inode_info_header *sih,
                    int link_change, int size_change,
                    in_pkg_param_t *in_param, out_pkg_param_t *out_param)
{
    obj_mgr_t *obj_mgr = sbi->pack_layout.obj_mgr;
    struct hk_obj_attr *attr;
    fill_attr_t attr_param;
    fill_param_t fill_param;
    attr_update_t attr_update;
    int ret = 0;

    ret = reserve_pkg_space(obj_mgr, &out_param->addr, TL_MTA_PKG_ATTR, MTA_PKG_ATTR_BLK);
    if (ret) {
        goto out;
    }

    attr = (struct hk_obj_attr *)(out_param->addr);
    attr_param.options = FILL_ATTR_EXIST | (FILL_ATTR_SIZE_CHANGE | FILL_ATTR_LINK_CHANGE);
    attr_param.inherit = sih;
    attr_param.size_change = size_change;
    attr_param.link_change = link_change;
    attr_param.update = &attr_update;
    fill_param.ino = sih->ino;
    fill_param.data = &attr_param;
    __fill_pm_attr(sbi, attr, &fill_param);
    commit_pkg(sbi, (void *)(out_param->addr), OBJ_ATTR_SIZE, &attr->hdr);

    attr_update.from_pkg = PKG_ATTR;
    ur_dram_latest_attr(obj_mgr, sih, &attr_update);

out:
    return ret;
}

int create_rename_pkg(struct hk_sb_info *sbi, const char *new_name,
                      obj_ref_dentry_t *ref, struct hk_inode_info_header *sih,
                      struct hk_inode_info_header *psih, struct hk_inode_info_header *npsih,
                      out_pkg_param_t *unlink_out_param, out_pkg_param_t *create_out_param)
{
    in_pkg_param_t in_param;
    in_create_pkg_param_t in_create_param;
    obj_mgr_t *obj_mgr = sbi->pack_layout.obj_mgr;
    u64 pkg_unlink_addr = 0;
    u64 pkg_create_addr = 0;
    int ret = 0;

    ret = reserve_pkg_space(obj_mgr, &pkg_unlink_addr, TL_MTA_PKG_UNLINK, MTA_PKG_UNLINK_BLK);
    if (ret) {
        goto out;
    }

    ret = reserve_pkg_space(obj_mgr, &pkg_create_addr, TL_MTA_PKG_CREATE, MTA_PKG_CREATE_BLK);
    if (ret) {
        goto out;
    }

    in_param.bin = 1;
    in_param.bin_type = BIN_RENAME;

    in_param.cur_pkg_addr = pkg_unlink_addr;
    in_param.next_pkg_addr = pkg_create_addr;
    create_unlink_pkg(sbi, sih, psih, ref, &in_param, unlink_out_param);

    obj_mgr_unload_imap_control(obj_mgr, sih);

    in_create_param.create_type = CREATE_FOR_RENAME;
    in_create_param.new_ino = (u32)-1;

    in_param.cur_pkg_addr = pkg_create_addr;
    in_param.next_pkg_addr = unlink_out_param->addr;
    in_param.private = &in_create_param;
    create_new_inode_pkg(sbi, sih->i_mode, new_name, sih, npsih, &in_param, create_out_param);

out:
    return ret;
}

int create_symlink_pkg(struct hk_sb_info *sbi, u16 mode, const char *name, const char *symname, u32 ino,
                       u64 symaddr, struct hk_inode_info_header *sih, struct hk_inode_info_header *psih,
                       out_pkg_param_t *data_out_param, out_pkg_param_t *create_out_param)
{
    in_pkg_param_t in_param;
    in_create_pkg_param_t in_create_param;
    obj_mgr_t *obj_mgr = sbi->pack_layout.obj_mgr;
    int ret = 0;

    in_create_param.new_ino = ino;
    in_create_param.create_type = CREATE_FOR_SYMLINK;
    in_param.private = &in_create_param;

    in_param.bin = 1;
    in_param.bin_type = PKG_SYMLINK;
    in_param.next_pkg_addr = 0;
    create_data_pkg(sbi, sih, symaddr, 0, HK_LBLK_SZ(sbi), 1, &in_param, data_out_param);

    in_param.next_pkg_addr = data_out_param->addr;
    create_new_inode_pkg(sbi, mode, name, sih, psih, &in_param, create_out_param);

out:
    return ret;
}
