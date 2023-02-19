#include "hunter.h"

/* Global Usage */
int do_reclaim_dram_pkg(struct hk_sb_info *sbi, obj_mgr_t *mgr, u64 pkg_addr, u16 pkg_type);
static int reserve_pkg_space(obj_mgr_t *mgr, u64 *pm_addr, u16 m_alloc_type);

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

inline obj_ref_attr_t *ref_attr_create(u64 addr, u32 ino, u16 from_pkg, u32 dep_addr)
{
    obj_ref_attr_t *ref = hk_alloc_obj_ref_attr();
    ref->hdr.ref = 1;
    ref->hdr.addr = addr;
    ref->hdr.ino = ino;
    ref->from_pkg = from_pkg;
    ref->dep_addr = dep_addr;
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

inline obj_ref_data_t *ref_data_create(u64 addr, u32 ino, u64 ofs, u64 num, u64 data_offset)
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
    hash_init(mgr->prealloc_imap.map);
    hash_init(mgr->pending_table);
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
    d_obj_ref_list_t *d_obj_list;
    obj_ref_data_t *ref_data;
    obj_ref_dentry_t *ref_dentry;
    struct list_head *pos, *n;
    d_root_t *root;
    int bkt, root_id;
    struct hlist_node *temp;

    if (mgr) {
        hash_for_each_safe(mgr->prealloc_imap.map, bkt, temp, cur, hnode)
        {
            hash_del(&cur->hnode);
            if (cur->latest_fop.latest_attr) 
                ref_attr_destroy(cur->latest_fop.latest_attr);
            if (cur->latest_fop.latest_inode)
                ref_inode_destroy(cur->latest_fop.latest_inode);
            cur->latest_fop.latest_attr = NULL;
            cur->latest_fop.latest_inode = NULL;
            hk_free_hk_inode_info_header(cur);
        }

        for (root_id = 0; root_id < mgr->num_d_roots; root_id++) {
            root = &mgr->d_roots[root_id];
            /* free ref_data and ref_dentry in d_roots */
            hash_for_each_safe(root->data_obj_refs, bkt, temp, d_obj_list, hnode)
            {
                list_for_each_safe(pos, n, &d_obj_list->list) {
                    ref_data = list_entry(pos, obj_ref_data_t, node);
                    list_del(pos);
                    ref_data_destroy(ref_data);
                }
                hash_del(&d_obj_list->hnode);
                kfree(d_obj_list);
            }

            hash_for_each_safe(root->dentry_obj_refs, bkt, temp, d_obj_list, hnode)
            {
                list_for_each_safe(pos, n, &d_obj_list->list) {
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
void *hk_lookup_d_obj_ref_lists(d_root_t *root, u64 ino, u8 type)
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

int obj_mgr_get_dobjs(obj_mgr_t *mgr, u64 ino, u8 type, void **obj_refs)
{
    struct hk_layout_info *layout;
    struct hk_sb_info *sbi = mgr->sbi;
    d_obj_ref_list_t *data_list = NULL, *dentry_list = NULL;
    d_root_t *root;

    layout = &sbi->layouts[get_layout_idx(sbi, ino)];
    root = &mgr->d_roots[layout->cpuid];

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

    hash_add(imap->map, &sih->hnode, sih->ino);

    return ret;
}

int obj_mgr_unload_imap_control(obj_mgr_t *mgr, struct hk_inode_info_header *sih)
{
    int ret = 0;
    imap_t *imap = &mgr->prealloc_imap;

    hash_del(&sih->hnode);

    return ret;
}

struct hk_inode_info_header *obj_mgr_get_imap_inode(obj_mgr_t *mgr, u32 ino)
{
    imap_t *imap = &mgr->prealloc_imap;
    struct hk_inode_info_header *sih;

    hash_for_each_possible(imap->map, sih, hnode, ino)
    {
        if (sih->ino == ino) {
            return sih;
        }
    }

    return NULL;
}

static claim_req_t *claim_req_create(u64 req_addr, u64 dep_addr, u16 req_type, u16 dep_type)
{
    claim_req_t *req = hk_alloc_claim_req();
    req->req_pkg_addr = req_addr;
    req->dep_pkg_addr = dep_addr;
    req->req_pkg_type = req_type;
    req->dep_pkg_type = dep_type;
    return req;
}

static void claim_req_destroy(claim_req_t *req)
{
    if (req) {
        hk_free_claim_req(req);
    }
}

/* For now, only handle UNLINK request */
int obj_mgr_send_claim_request(obj_mgr_t *mgr, claim_req_t *req)
{
    hash_add(mgr->pending_table, &req->hnode, req->dep_pkg_addr);
    return 0;
}

claim_req_t *obj_mgr_get_claim_request(obj_mgr_t *mgr, u64 dep_pkg_addr)
{
    claim_req_t *req;

    hash_for_each_possible(mgr->pending_table, req, hnode, dep_pkg_addr)
    {
        if (req->dep_pkg_addr == dep_pkg_addr) {
            return req;
        }
    }
    return NULL;
}

int obj_mgr_process_claim_request(obj_mgr_t *mgr, u64 dep_pkg_addr)
{
    struct hlist_head *pending_table = mgr->pending_table;
    struct hk_sb_info *sbi = mgr->sbi;
    claim_req_t *req = obj_mgr_get_claim_request(mgr, dep_pkg_addr);
    int ret = 0;
    if (req) {
        /* we've finish processing the request */
        hash_del(&req->hnode);
        ret = do_reclaim_dram_pkg(sbi, mgr, req->req_pkg_addr, req->req_pkg_type);
        if (ret == 0) {
            hk_dbg("Claim request (0x%lx, 0x%lx) is processed\n", req->req_pkg_addr, req->dep_pkg_addr);
        }
        claim_req_destroy(req);
    }
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

out:
    return param.freed;
}

/* Called when new attr is emerged */
int reclaim_dram_unlink(obj_mgr_t *mgr, struct hk_inode_info_header *sih)
{
    struct hk_sb_info *sbi = mgr->sbi;
    obj_ref_attr_t *ref_attr = sih->latest_fop.latest_attr;
    struct hk_pkg_hdr *pkg_hdr;
    claim_req_t *req;
    u32 cur_ofs;
    u32 dep_ofs;
    int ret = 0;

    if (ref_attr == NULL) {
        return -EINVAL;
    }

    cur_ofs = ref_attr->hdr.addr;
    dep_ofs = ref_attr->dep_addr;

    req = claim_req_create(get_pm_addr(sbi, cur_ofs), get_pm_addr(sbi, dep_ofs), PKG_UNLINK, PKG_CREATE);
    if (req == NULL) {
        return -ENOMEM;
    }

    ret = obj_mgr_send_claim_request(mgr, req);
    if (ret) {
        return ret;
    }

    return 0;
}

int reclaim_dram_create(obj_mgr_t *mgr, struct hk_inode_info_header *sih, obj_ref_dentry_t *ref)
{
    struct hk_sb_info *sbi = mgr->sbi;
    u64 pkg_addr = get_pm_addr(sbi, sih->latest_fop.latest_inode->hdr.addr);
    d_root_t *root = &mgr->d_roots[get_layout_idx(sbi, sih->latest_fop.latest_inode->hdr.addr)];
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
    obj_ref_attr_t *ref = sih->latest_fop.latest_attr;
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
    sih->latest_fop.latest_attr = NULL;
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
    u32 est_ofs_blk, est_num;
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

        if (behind_remained_blks == 0) {
            /* completely overlapped */
            reclaimed_blks = est_num - before_remained_blks;
        } else {
            /* partially overlapped */
            reclaimed_blks = update->num;
        }

        if (behind_remained_blks > 0) {
            u32 length = ((est_num - behind_remained_blks) << HUNTER_BLK_SHIFT);
            u32 new_data_ofs = ref->data_offset + length;
            u32 new_ofs = ref->ofs + length;
            u32 new_addr = ref->hdr.addr + length;
            u64 addr;

            ret = reserve_pkg_space(mgr, &addr, TL_MTA_PKG_DATA);
            if (ret) {
                return ret;
            }

            new_ref = ref_data_create(get_pm_offset(sbi, addr), sih->ino, new_ofs, behind_remained_blks, new_data_ofs);
            linix_insert(&sih->ix, GET_ALIGNED_BLKNR(new_ofs), new_ref, false);
            obj_mgr_load_dobj_control(mgr, (void *)new_ref, OBJ_DATA);
        }

        if (before_remained_blks == 0) {
            linix_insert(&sih->ix, est_ofs_blk, NULL, false);
            ref->hdr.ref--;
            obj_mgr_unload_dobj_control(mgr, (void *)ref, OBJ_DATA);
            do_reclaim_dram_pkg(sbi, mgr, get_pm_addr(sbi, ref->hdr.addr), PKG_DATA);
            ref_data_destroy(ref);
        } else {
            ref->num = before_remained_blks;
        }

        /* release data blocks */
        layout = &sbi->layouts[get_layout_idx(sbi, ref->data_offset)];
        tl_build_free_param(&param, old_blk, reclaimed_blks, TL_BLK);
        tlfree(&layout->allocator, &param);

        update->num = before_remained_blks + update->num - est_num;
        if (update->num > 0) {
            update->blk = est_ofs_blk + est_num;
            update->ofs = ref->ofs + ((est_num - before_remained_blks) << HUNTER_BLK_SHIFT);
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

    if (!sih->latest_fop.latest_inode) {
        sih->latest_fop.latest_inode = ref_inode_create(pm_inode, sih->ino);
    } else {
        sih->latest_fop.latest_inode->hdr.addr = pm_inode;
    }
    sih->ino = ino;
    return 0;
}

/* update and reclaim in-DRAM attr, called when rename/create/truncate invoked */
int ur_dram_latest_attr(obj_mgr_t *mgr, struct hk_inode_info_header *sih, attr_update_t *update)
{
    reclaim_dram_attr(mgr, sih);
    if (!sih->latest_fop.latest_attr) {
        sih->latest_fop.latest_attr = ref_attr_create(update->addr, sih->ino, update->from_pkg, update->dep_addr);
    } else {
        sih->latest_fop.latest_attr->hdr.addr = update->addr;
        sih->latest_fop.latest_attr->from_pkg = update->from_pkg;
        sih->latest_fop.latest_attr->dep_addr = update->dep_addr;
    }
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
    return 0;
}

/* == In-PM pkg managements == */
int reserve_pkg_space_in_layout(obj_mgr_t *mgr, struct hk_layout_info *layout, u64 *pm_addr, u32 num, u16 m_alloc_type)
{
    struct hk_sb_info *sbi = mgr->sbi;
    tl_allocator_t *alloc = &layout->allocator;
    tlalloc_param_t param;
    u32 addr, entrynr;
    s32 ret = 0;
    INIT_TIMING(time);

    HK_START_TIMING(reserve_pkg_in_layout_t, time);
    tl_build_alloc_param(&param, num, TL_MTA | m_alloc_type);
    ret = tlalloc(alloc, &param);
    if (ret) {
        hk_dbgv("%s failed %d\n", __func__, ret);
        goto out;
    }

    addr = param._ret_rng.low;
    entrynr = param._ret_rng.high;

    *pm_addr = get_pm_entry_addr(sbi, addr, entrynr);

out:
    HK_END_TIMING(reserve_pkg_in_layout_t, time);
    return ret;
}

static int reserve_pkg_space(obj_mgr_t *mgr, u64 *pm_addr, u16 m_alloc_type)
{
    struct hk_sb_info *sbi = mgr->sbi;
    struct super_block *sb = sbi->sb;
    struct hk_layout_info *layout;
    u32 num = 0;
    u32 start_cpuid, cpuid, i;
    bool found = false;
    int ret = 0;
    INIT_TIMING(time);

    HK_START_TIMING(reserve_pkg_t, time);
    switch (m_alloc_type) {
    case TL_MTA_PKG_ATTR: /* fop: truncate operations */
        num = MTA_PKG_ATTR_BLK;
        break;
    case TL_MTA_PKG_UNLINK: /* fop: unlink operations */
        num = MTA_PKG_UNLINK_BLK;
        break;
    case TL_MTA_PKG_CREATE: /* fop: create/mkdir operations */
        num = MTA_PKG_CREATE_BLK;
        break;
    case TL_MTA_PKG_DATA: /* I/O: write operations */
        num = MTA_PKG_DATA_BLK;
        break;
    default:
        break;
    }

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

    if (attr_param->update) {
        attr_param->update->i_mode = i_mode;
        attr_param->update->i_atime = i_atime;
        attr_param->update->i_ctime = i_ctime;
        attr_param->update->i_mtime = i_mtime;
        attr_param->update->i_size = i_size;
        attr_param->update->i_uid = i_uid;
        attr_param->update->i_gid = i_gid;
        attr_param->update->i_links_count = i_links_count;
        attr_param->update->addr = get_pm_offset(sbi, attr);
        attr_param->update->from_pkg = PKG_CREATE;
        attr_param->update->dep_addr = 0;
    }

    __fill_pm_obj_hdr(sbi, &attr->hdr, OBJ_ATTR);
    hk_memlock_range(sb, attr, sizeof(struct hk_obj_attr), &flags);
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
    memcpy_to_pmem_nocache(dentry->name, dentry_param->name, dentry_param->len);
    dentry->name[dentry_param->len] = '\0';
    __fill_pm_obj_hdr(sbi, &dentry->hdr, OBJ_DENTRY);
    hk_memlock_range(sb, dentry, sizeof(struct hk_obj_dentry), &flags);
}

typedef struct fill_pkg_hdr {
    u16 type; /* this package type */
    union {
        /* for unlink operations */
        struct {
            u32 unlinked_ino;
        };
        /* for rename */
        struct {
            u32 link;
        };
    };
} fill_pkg_hdr_t;

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
    case PKG_CREATE:
        break;
    case PKG_UNLINK:
        pkg_hdr->unlink_hdr.unlinked_ino = pkg_hdr_param->unlinked_ino;
        break;
    case PKG_RENAME:
        pkg_hdr->rename_hdr.next = pkg_hdr_param->link;
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

    if (!hk_crc32c(~0, (const char *)obj_start, len) == crc32) {
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
    obj_mgr_t *obj_mgr = sbi->obj_mgr;
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

    if (strlen(name) > HK_NAME_LEN) {
        return -ENAMETOOLONG;
    }

    switch (create_type)
    {
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

    ret = reserve_pkg_space(obj_mgr, &out_param->addr, TL_MTA_PKG_CREATE);
    if (ret) {
        goto out;
    }

    fill_attr_t attr_param;
    cur_addr = out_param->addr;
    if (create_type == CREATE_FOR_RENAME) {
        hk_dbg("create inode pkg, ino: %u, addr: 0x%llx, offset: 0x%llx\n", ino, cur_addr, get_pm_offset(sbi, cur_addr));

        /* fill inode from existing inode */
        obj_inode = (struct hk_obj_inode *)cur_addr;
        inode_update.sih = sih;
        __fill_pm_inode_from_exist(sbi, obj_inode, &inode_update);
        cur_addr += OBJ_INODE_SIZE;

        /* fill attr */
        attr_param.mode = mode;
        attr_param.options = FILL_ATTR_EXIST | FILL_ATTR_INHERIT;
        attr_param.inherit = sih;
        attr_param.update = &attr_update;

        fill_param.ino = ino;
        fill_param.data = &attr_param;
        attr = (struct hk_obj_attr *)cur_addr;
        __fill_pm_attr(sbi, attr, &fill_param);
        cur_addr += OBJ_ATTR_SIZE;
    } else {
        if (create_type == CREATE_FOR_LINK)
            hk_dbg("create new inode pkg, ino: %u (-> %u), addr: 0x%llx, offset: 0x%llx\n", ino, orig_ino, cur_addr, get_pm_offset(sbi, cur_addr));
        else if (create_type == CREATE_FOR_SYMLINK)
            hk_dbg("create new inode pkg, ino: %u (symdata @ 0x%llx), addr: 0x%llx, offset: 0x%llx\n", ino, in_param->next, cur_addr, get_pm_offset(sbi, cur_addr));
        else 
            hk_dbg("create new inode pkg, ino: %u, addr: 0x%llx, offset: 0x%llx\n", ino, cur_addr, get_pm_offset(sbi, cur_addr));

        /* fill inode */
        obj_inode = (struct hk_obj_inode *)cur_addr;
        __fill_pm_inode(sbi, obj_inode, ino, rdev, &inode_update);
        cur_addr += OBJ_INODE_SIZE;

        /* fill attr */
        attr_param.mode = mode;
        attr_param.options = FILL_ATTR_INIT;
        attr_param.inherit = NULL;
        attr_param.update = &attr_update;

        if (create_type == CREATE_FOR_LINK)
            fill_param.ino = orig_ino;
        else
            fill_param.ino = ino;

        fill_param.data = &attr_param;
        attr = (struct hk_obj_attr *)cur_addr;
        __fill_pm_attr(sbi, attr, &fill_param);
        cur_addr += OBJ_ATTR_SIZE;
    }

    /* fill parent attr */
    /* if it is root inode, there is no parent inode */
    pattr = (struct hk_obj_attr *)cur_addr;
    if (psih) {
        attr_param.options = FILL_ATTR_EXIST | (FILL_ATTR_LINK_CHANGE | FILL_ATTR_SIZE_CHANGE);
        attr_param.link_change = 1;
        attr_param.size_change = OBJ_DENTRY_SIZE;
        attr_param.inherit = psih;
        attr_param.update = &pattr_update;
        fill_param.data = &attr_param;
        __fill_pm_attr(sbi, pattr, &fill_param);
    } else {
        memset_nt(pattr, 0, OBJ_ATTR_SIZE);
    }
    cur_addr += OBJ_ATTR_SIZE;

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
    if (in_param->partial) {
        pkg_hdr_param.type = in_param->wrapper_pkg_type;
        pkg_hdr_param.link = in_param->next;
    } else {
        pkg_hdr_param.type = PKG_CREATE;
    }
    fill_param.data = &pkg_hdr_param;
    __fill_pm_pkg_hdr(sbi, pkg_hdr, &fill_param);
    cur_addr += OBJ_PKGHDR_SIZE;

    /* flush + fence-once to commit the package */
    commit_pkg(sbi, (void *)(out_param->addr), cur_addr - out_param->addr, &pkg_hdr->hdr);

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
    return ret;
}

/* remove dentry in pfi first. Then hold dentry's ref to process unlink pkg creation */
/* note: drop fi's latest fop outside */
int create_unlink_pkg(struct hk_sb_info *sbi, struct hk_inode_info_header *sih,
                      struct hk_inode_info_header *psih, obj_ref_dentry_t *ref,
                      in_pkg_param_t *in_param, out_pkg_param_t *out_param)
{
    obj_mgr_t *obj_mgr = sbi->obj_mgr;
    inode_mgr_t *inode_mgr = sbi->inode_mgr;
    struct hk_obj_attr *pattr;
    attr_update_t pattr_update;
    fill_param_t fill_param;
    u64 cur_addr;
    int ret;

    ret = reserve_pkg_space(obj_mgr, &out_param->addr, TL_MTA_PKG_UNLINK);
    if (ret) {
        goto out;
    }

    cur_addr = out_param->addr;

    /* fill parent attr */
    fill_attr_t attr_param = {
        .options = FILL_ATTR_EXIST | (FILL_ATTR_SIZE_CHANGE | FILL_ATTR_LINK_CHANGE),
        .inherit = psih,
        .update = &pattr_update,
    };
    attr_param.link_change = -1;
    attr_param.size_change = -OBJ_DENTRY_SIZE;
    fill_param.ino = psih->ino;
    fill_param.data = &attr_param;
    pattr = (struct hk_obj_attr *)cur_addr;
    __fill_pm_attr(sbi, pattr, &fill_param);
    cur_addr += OBJ_ATTR_SIZE;

    /* fill pkg hdr */
    fill_pkg_hdr_t pkg_hdr_param;
    struct hk_pkg_hdr *pkg_hdr = (struct hk_pkg_hdr *)cur_addr;
    if (in_param->partial) {
        pkg_hdr_param.type = in_param->wrapper_pkg_type;
        pkg_hdr_param.link = in_param->next;
    } else {
        pkg_hdr_param.type = PKG_UNLINK;
    }
    fill_param.data = &pkg_hdr_param;
    __fill_pm_pkg_hdr(sbi, pkg_hdr, &fill_param);
    cur_addr += OBJ_PKGHDR_SIZE;

    /* flush + fence-once to commit the package */
    commit_pkg(sbi, (void *)(out_param->addr), cur_addr - out_param->addr, &pkg_hdr->hdr);

    /* handle dram updates */
    pattr_update.from_pkg = PKG_UNLINK;
    pattr_update.dep_addr = get_pm_offset(sbi, sih->latest_fop.latest_inode->hdr.addr);
    ur_dram_latest_attr(obj_mgr, psih, &pattr_update);

    /* remove existing create pkg */
    reclaim_dram_create(obj_mgr, sih, ref);

    /* unload inode from imap */
    obj_mgr_unload_imap_control(obj_mgr, sih);
out:
    return ret;
}

int create_data_pkg(struct hk_sb_info *sbi, struct hk_inode_info_header *sih,
                    u64 data_addr, off_t offset, size_t size,
                    in_pkg_param_t *in_param, out_pkg_param_t *out_param)
{
    obj_mgr_t *obj_mgr = sbi->obj_mgr;
    struct hk_obj_data *data;
    struct hk_inode_info *si;
    data_update_t data_update;
    size_t aligned_size = _round_up(size, HK_LBLK_SZ(sbi));
    size_t size_after_write = offset + size > sih->i_size ? offset + size : sih->i_size;
    u64 blk = 0, num = 0;
    int ret = 0;
    INIT_TIMING(time);

    HK_START_TIMING(new_data_trans_t, time);
    ret = reserve_pkg_space(obj_mgr, &out_param->addr, TL_MTA_PKG_DATA);
    if (ret) {
        goto out;
    }

    data = (struct hk_obj_data *)(out_param->addr);

    data->ino = sih->ino;
    data->blk = blk = get_pm_blk(sbi, data_addr);
    data->ofs = offset;
    data->num = num = (aligned_size >> HUNTER_BLK_SHIFT);
    data->i_cmtime = sih->i_ctime;
    data->i_size = size_after_write;
    if (in_param->partial) {
        __fill_pm_obj_hdr(sbi, &data->hdr, OBJ_DATA | in_param->wrapper_pkg_type);
    } else {
        __fill_pm_obj_hdr(sbi, &data->hdr, OBJ_DATA);
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

    HK_END_TIMING(new_data_trans_t, time);
out:
    return ret;
}

/* this would change in dram structure, so just call it  */
int create_attr_pkg(struct hk_sb_info *sbi, struct hk_inode_info_header *sih,
                    int link_change, int size_change,
                    in_pkg_param_t *in_param, out_pkg_param_t *out_param)
{
    obj_mgr_t *obj_mgr = sbi->obj_mgr;
    struct hk_obj_attr *attr;
    fill_attr_t attr_param;
    fill_param_t fill_param;
    attr_update_t attr_update;
    int ret = 0;

    ret = reserve_pkg_space(obj_mgr, &out_param->addr, TL_MTA_PKG_ATTR);
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
    obj_mgr_t *obj_mgr = sbi->obj_mgr;

    in_create_param.create_type = CREATE_FOR_RENAME;
    in_create_param.new_ino = (u32)-1;
    in_param.private = &in_create_param;

    in_param.partial = 1;
    in_param.wrapper_pkg_type = PKG_RENAME;
    in_param.next = 0;
    create_unlink_pkg(sbi, sih, psih, ref, &in_param, unlink_out_param);

    in_param.next = unlink_out_param->addr;
    create_new_inode_pkg(sbi, sih->i_mode, new_name, sih, npsih, &in_param, create_out_param);

    return 0;
}

int create_symlink_pkg(struct hk_sb_info *sbi, u16 mode, const char *name, const char *symname, u32 ino,
                       u64 symaddr, struct hk_inode_info_header *sih, struct hk_inode_info_header *psih,
                       out_pkg_param_t *data_out_param, out_pkg_param_t *create_out_param)
{
    in_pkg_param_t in_param;
    in_create_pkg_param_t in_create_param;
    obj_mgr_t *obj_mgr = sbi->obj_mgr;
    int ret = 0;

    in_create_param.new_ino = ino;
    in_create_param.create_type = CREATE_FOR_SYMLINK;
    in_param.private = &in_create_param;

    in_param.partial = 1;
    in_param.wrapper_pkg_type = PKG_SYMLINK;
    in_param.next = 0;
    create_data_pkg(sbi, sih, symaddr, 0, HK_LBLK_SZ(sbi), &in_param, data_out_param);

    in_param.next = data_out_param->addr;
    create_new_inode_pkg(sbi, mode, name, sih, psih, &in_param, create_out_param);

out:
    return ret;
}
