#include "hunter.h"

wait_queue_head_t cmt_finish_wq;
int cmt_finished[HK_CMT_WORKER_NUM];
int hk_request_cmt(struct super_block *sb, void *info, struct hk_inode_info_header *sih);

static void wait_to_finish_cmt(void)
{
    int i;

    for (i = 0; i < HK_CMT_WORKER_NUM; i++) {
        while (cmt_finished[i] == 0) {
            wait_event_interruptible_timeout(cmt_finish_wq, false,
                                             msecs_to_jiffies(1));
        }
    }
}

/* ===== High-level ===== */
void hk_checkpoint_inode_state(struct inode *inode, struct hk_cmt_icp *icp)
{
    struct hk_inode_info_header *sih = HK_IH(inode);

    icp->ino = inode->i_ino;
    icp->atime = inode->i_atime.tv_sec;
    icp->mtime = inode->i_mtime.tv_sec;
    icp->ctime = inode->i_ctime.tv_sec;
    icp->size = inode->i_size;
    icp->mode = inode->i_mode;
    icp->uid = i_uid_read(inode);
    icp->gid = i_gid_read(inode);
    icp->generation = inode->i_generation;
    icp->flags = inode->i_flags;
    icp->tstamp = sih->tstamp;
    icp->links_count = inode->i_nlink;
}

void *__hk_generic_info_init(enum hk_cmt_info_type type)
{
    void *info = NULL;

    switch (type) {
    case CMT_VALID_DATA:
    case CMT_INVALID_DATA:
        info = hk_alloc_hk_cmt_data_info();
        break;
    case CMT_NEW_INODE:
        info = hk_alloc_hk_cmt_new_inode_info();
        break;
    case CMT_UNLINK_INODE:
        info = hk_alloc_hk_cmt_unlink_inode_info();
        break;
    case CMT_DELETE_INODE:
        info = hk_alloc_hk_cmt_delete_inode_info();
        break;
    case CMT_CLOSE_INODE:
        info = hk_alloc_hk_cmt_close_info();
        break;
    default:
        break;
    }

    ((struct hk_cmt_info *)info)->type = type;
    INIT_LIST_HEAD(&((struct hk_cmt_info *)info)->lnode);

    return info;
}

int hk_delegate_data_async(struct super_block *sb, struct inode *inode, struct hk_cmt_dbatch *batch, enum hk_cmt_info_type type)
{
    struct hk_cmt_data_info *data_info;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info_header *sih = HK_IH(inode);

    BUG_ON(batch->addr_start == 0);

    data_info = __hk_generic_info_init(type);

    data_info->addr_start = batch->addr_start;
    data_info->addr_end = batch->addr_end;
    data_info->blk_start = batch->blk_start;
    data_info->blk_end = batch->blk_end;
    data_info->tstamp = get_version(sbi);

    hk_request_cmt(sb, data_info, sih);

    return 0;
}

int hk_delegate_create_async(struct super_block *sb, struct inode *inode, struct inode *dir, struct hk_dentry *direntry)
{
    struct hk_cmt_new_inode_info *new_inode_info;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info_header *sih = HK_IH(inode);

    new_inode_info = __hk_generic_info_init(CMT_NEW_INODE);
    hk_checkpoint_inode_state(inode, &new_inode_info->inode_cp);
    hk_checkpoint_inode_state(dir, &new_inode_info->dir_inode_cp);
    new_inode_info->direntry = direntry;

    hk_request_cmt(sb, new_inode_info, sih);

    return 0;
}

int hk_delegate_unlink_async(struct super_block *sb, struct inode *inode, struct inode *dir, struct hk_dentry *direntry, bool invalidate)
{
    struct hk_cmt_unlink_inode_info *unlink_info;
    struct hk_inode_info_header *sih = HK_IH(inode);

    unlink_info = __hk_generic_info_init(CMT_UNLINK_INODE);
    hk_checkpoint_inode_state(inode, &unlink_info->inode_cp);
    hk_checkpoint_inode_state(dir, &unlink_info->dir_inode_cp);
    unlink_info->direntry = direntry;
    unlink_info->invalidate = invalidate;

    hk_request_cmt(sb, unlink_info, sih);

    return 0;
}

int hk_delegate_delete_async(struct super_block *sb, struct inode *inode)
{
    struct hk_cmt_delete_inode_info *delete_info;
    struct hk_inode_info_header *sih = HK_IH(inode);

    delete_info = __hk_generic_info_init(CMT_DELETE_INODE);

    hk_request_cmt(sb, delete_info, sih);
}

int hk_delegate_close_async(struct super_block *sb, struct inode *inode)
{
    struct hk_cmt_close_info *close_info;
    struct hk_inode_info_header *sih = HK_IH(inode);

    close_info = __hk_generic_info_init(CMT_CLOSE_INODE);

    hk_request_cmt(sb, close_info, sih);

    return 0;
}

void hk_cmt_info_destroy(void *cmt_info)
{
    struct hk_cmt_info *info = cmt_info;
    switch (info->type) {
    case CMT_VALID_DATA:
    case CMT_INVALID_DATA:
        hk_free_hk_cmt_data_info((struct hk_cmt_data_info *)info);
        break;
    case CMT_NEW_INODE:
        hk_free_hk_cmt_new_inode_info((struct hk_cmt_new_inode_info *)info);
        break;
    case CMT_UNLINK_INODE:
        hk_free_hk_cmt_unlink_inode_info((struct hk_cmt_unlink_inode_info *)info);
        break;
    case CMT_DELETE_INODE:
        hk_free_hk_cmt_delete_inode_info((struct hk_cmt_delete_inode_info *)info);
        break;
    case CMT_CLOSE_INODE:
        hk_free_hk_cmt_close_info((struct hk_cmt_close_info *)info);
        break;
    default:
        break;
    }
}

/* ===== Process ===== */
int hk_process_data_info(struct super_block *sb, u64 ino, struct hk_cmt_data_info *data_info)
{
    struct hk_header *hdr;
    struct hk_layout_info *layout = NULL;
    u64 addr, blk;
    u64 addr_start = data_info->addr_start;
    u64 addr_end = data_info->addr_end;
    u64 blk_start = data_info->blk_start;

    hdr = sm_get_hdr_by_addr(sb, addr_start);
    layout = sm_get_layout_by_hdr(sb, hdr);

    use_layout(layout);
    for (addr = addr_start, blk = blk_start; addr < addr_end; addr += HK_PBLK_SZ, blk += 1) {
        hdr = sm_get_hdr_by_addr(sb, addr);
        switch (data_info->type) {
        case CMT_VALID_DATA: {
            sm_valid_data_sync(sb, addr, ino, blk, data_info->tstamp);
            break;
        }
        case CMT_INVALID_DATA: {
            if (hdr->tstamp <= data_info->tstamp) {
                sm_invalid_data_sync(sb, addr, ino);
            } else {
                BUG_ON(1);
            }
            break;
        }
        default:
            break;
        }
    }
    unuse_layout(layout);
}

extern int hk_start_tx_for_new_inode(struct super_block *sb, u64 ino, struct hk_dentry *direntry,
                                     u64 dir_ino, umode_t mode);

int hk_process_new_inode_info(struct super_block *sb, u64 ino, struct hk_cmt_new_inode_info *new_inode_info)
{
    unsigned long irq_flags = 0;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode *pi = hk_get_pi_by_ino(sb, ino);
    u64 pidir_ino = new_inode_info->dir_inode_cp.ino;
    int txid = 0;

    hk_commit_icp(sb, &new_inode_info->inode_cp);

    txid = hk_start_tx_for_new_inode(sb, ino, new_inode_info->direntry, pidir_ino, new_inode_info->inode_cp.mode);
    if (txid < 0) {
        hk_dbgv("hk_start_tx_for_new_inode failed\n");
        return txid;
    }
    hk_commit_icp_attrchange(sb, &new_inode_info->dir_inode_cp);
    hk_finish_tx(sb, txid);
}

extern int hk_start_tx_for_unlink(struct super_block *sb, struct hk_inode *pi,
                                  struct hk_dentry *direntry, struct hk_inode *pidir,
                                  bool invalidate);

int hk_process_unlink_info(struct super_block *sb, u64 ino, struct hk_cmt_unlink_inode_info *unlink_info)
{
    unsigned long irq_flags = 0;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode *pi = hk_get_pi_by_ino(sb, ino);
    u64 pidir_ino = unlink_info->dir_inode_cp.ino;
    int txid = 0;

    txid = hk_start_tx_for_unlink(sb, pi, unlink_info->direntry, pidir_ino, unlink_info->invalidate);
    if (txid < 0) {
        hk_dbgv("hk_start_tx_for_unlink failed\n");
        return txid;
    }
    hk_commit_icp_attrchange(sb, &unlink_info->inode_cp);
    hk_commit_icp_linkchange(sb, &unlink_info->dir_inode_cp);
    hk_finish_tx(sb, txid);
}

extern int hk_free_ino(struct super_block *sb, u64 ino);

int hk_process_delete_info(struct super_block *sb, struct hk_cmt_node *cmt_node, struct hk_cmt_delete_inode_info *delete_info)
{
    u64 ino = cmt_node->ino;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode *pi = hk_get_pi_by_ino(sb, ino);
    struct hk_header *hdr, *n;
    unsigned long irq_flags = 0;
    u64 blk_addr;

    // Do not use this, this is a tag.
    (void)delete_info;

    hk_memunlock_pi(sb, pi, &irq_flags);
    pi->valid = 0;
    hk_flush_buffer(pi, sizeof(struct hk_inode), true);
    hk_memlock_pi(sb, pi, &irq_flags);

    // Tag data hdr as invalid, and release data asyncly
    traverse_inode_hdr_safe(sbi, pi, hdr, n)
    {
        blk_addr = sm_get_addr_by_hdr(sb, hdr);
        // hk_info("delete data blk %llu for %llu\n", hdr->f_blk, pi->ino);
        use_layout_for_addr(sb, blk_addr);
        sm_delete_data_sync(sb, blk_addr);
        unuse_layout_for_addr(sb, blk_addr);
    }

    // Release ino asyncly
    hk_free_ino(sb, ino);

    return 0;
}

int hk_process_close_info(struct super_block *sb, struct hk_cmt_node *cmt_node, struct hk_cmt_close_info *close_info)
{
    u64 ino = cmt_node->ino;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode *pi = hk_get_pi_by_ino(sb, ino);

    // Do not use this, this is a tag.
    (void)close_info;

    /* flush in-DRAM hdr address  */
    if (cmt_node->h_addr != 0) {
        if (cmt_node->h_addr != 0) {
            ((struct hk_header *)TRANS_OFS_TO_ADDR(sbi, cmt_node->h_addr))->ofs_prev = TRANS_ADDR_TO_OFS(sbi, pi);
        }
        pi->h_addr = cmt_node->h_addr;
    }

    return 0;
}

int hk_process_cmt_info(struct super_block *sb, struct hk_cmt_node *cmt_node, void *info, enum hk_cmt_info_type type)
{
    switch (type) {
    case CMT_VALID_DATA:
    case CMT_INVALID_DATA:
        hk_process_data_info(sb, cmt_node->ino, (struct hk_cmt_data_info *)info);
        break;
    case CMT_UNLINK_INODE:
        hk_process_unlink_info(sb, cmt_node->ino, (struct hk_cmt_unlink_inode_info *)info);
        break;
    case CMT_DELETE_INODE:
        hk_process_delete_info(sb, cmt_node, (struct hk_cmt_delete_inode_info *)info);
        break;
    case CMT_NEW_INODE:
        hk_process_new_inode_info(sb, cmt_node->ino, (struct hk_cmt_new_inode_info *)info);
        break;
    case CMT_CLOSE_INODE:
        hk_process_close_info(sb, cmt_node, (struct hk_cmt_close_info *)info);
        break;
    default:
        break;
    }

    hk_cmt_info_destroy(info);

    return 0;
}

/* ===== Low-level ===== */
struct hk_cmt_node *hk_cmt_node_init(u64 ino)
{
    struct hk_cmt_node *node = hk_alloc_hk_cmt_node();

    hk_inf_queue_init(&node->op_q);

    node->ino = ino;
    node->h_addr = 0;
    node->valid = 0;

    return node;
}

void hk_cmt_node_destroy(struct hk_cmt_node *node)
{
    if (node) {
        hk_free_hk_cmt_node(node);
    }
}

int hk_cmt_manage_node(struct super_block *sb, struct hk_cmt_node *cmt_node, struct hk_cmt_node **exist)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_cmt_queue *cq = sbi->cq;
    u64 ino = cmt_node->ino;
    struct rb_root *tree = &cq->cmt_forest[ino % HK_CMT_WORKER_NUM];
    struct mutex *lock = &cq->locks[ino % HK_CMT_WORKER_NUM];
    struct hk_cmt_node *curr;
    struct rb_node **temp, *parent;
    int compVal;

    temp = &(tree->rb_node);
    parent = NULL;

    mutex_lock(lock);

    while (*temp) {
        curr = container_of(*temp, struct hk_cmt_node, rnode);
        compVal = curr->ino > cmt_node->ino ? -1 : (curr->ino < cmt_node->ino ? 1 : 0);
        parent = *temp;

        if (compVal == -1) {
            temp = &((*temp)->rb_left);
        } else if (compVal == 1) {
            temp = &((*temp)->rb_right);
        } else {
            if (curr->valid == 1) {
                hk_dbgv("cmt node for inode %llu already exists\n", cmt_node->ino);
                mutex_unlock(lock);
                return -EINVAL;
            } else {
                curr->valid = 1;
                if (exist) {
                    *exist = curr;
                }
                hk_dbg("find an invalidated slot for request %llu to reuse\n", cmt_node->ino);
                mutex_unlock(lock);
                return -EEXIST;
            }
        }
    }

    rb_link_node(&cmt_node->rnode, parent, temp);
    rb_insert_color(&cmt_node->rnode, tree);

    if (exist) {
        *exist = NULL;
    }

    mutex_unlock(lock);

    return 0;
}

struct hk_cmt_node *hk_cmt_search_node(struct super_block *sb, u64 ino)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_cmt_queue *cq = sbi->cq;
    struct rb_root *tree = &cq->cmt_forest[ino % HK_CMT_WORKER_NUM];
    struct mutex *lock = &cq->locks[ino % HK_CMT_WORKER_NUM];
    struct hk_cmt_node *curr;
    struct rb_node **temp, *parent;
    int compVal;

    temp = &(tree->rb_node);
    parent = NULL;

    mutex_lock(lock);

    while (*temp) {
        curr = container_of(*temp, struct hk_cmt_node, rnode);
        compVal = curr->ino > ino ? -1 : (curr->ino < ino ? 1 : 0);
        parent = *temp;

        if (compVal == -1) {
            temp = &((*temp)->rb_left);
        } else if (compVal == 1) {
            temp = &((*temp)->rb_right);
        } else {
            mutex_unlock(lock);
            return curr;
        }
    }
    mutex_unlock(lock);

    return NULL;
}

int hk_cmt_unmanage_node(struct super_block *sb, struct hk_cmt_node *cmt_node)
{
    if (cmt_node) {
        cmt_node->valid = 0;
        return 0;
    } else {
        hk_dbgv("cmt node for inode %llu is not found\n", cmt_node->ino);
        return -EINVAL;
    }
}

void __hk_cmt_destroy_node_tree(struct super_block *sb, struct rb_root *tree)
{
    struct hk_cmt_node *curr;
    struct rb_node *temp;

    temp = rb_first(tree);
    while (temp) {
        curr = container_of(temp, struct hk_cmt_node, rnode);
        temp = rb_next(temp);
        rb_erase(&curr->rnode, tree);

        HK_ASSERT(hk_inf_queue_length(&curr->op_q) == 0);

        hk_cmt_node_destroy(curr);
    }
}

void hk_cmt_destory_forest(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_cmt_queue *cq = sbi->cq;
    int i;

    for (i = 0; i < HK_CMT_WORKER_NUM; i++) {
        __hk_cmt_destroy_node_tree(sb, &cq->cmt_forest[i]);
    }
}

int hk_request_cmt(struct super_block *sb, void *info, struct hk_inode_info_header *sih)
{
    struct hk_cmt_data_info *cmt_data = (struct hk_cmt_data_info *)info;
    hk_inf_queue_add_tail_locked(&sih->cmt_node->op_q, &cmt_data->lnode);
    return 0;
}

int hk_grab_cmt_info(struct super_block *sb, struct hk_cmt_node *cmt_node, void *info_head, int batch_num)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    int ret = 0;

    ret = hk_inf_queue_try_pop_front_batch_locked(&cmt_node->op_q, info_head, batch_num);

    return ret;
}

/* == Worker == */
struct hk_cmt_worker_param {
    struct super_block *sb;
    const char *name;
    int work_id;
};

static int hk_cmt_worker_thread(void *arg)
{
    struct hk_cmt_worker_param *param = (struct hk_cmt_worker_param *)arg;
    struct super_block *sb = param->sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    int work_id = param->work_id;

    allow_signal(SIGINT);

    struct hk_cmt_queue *cq = sbi->cq;
    struct hk_cmt_node *cmt_node, *cmt_node_next;
    struct hk_cmt_info *info, *info_next;
    struct list_head info_head;

    while (!kthread_should_stop()) {
        ssleep_interruptible(HK_CMT_TIME_GAP);

        rbtree_postorder_for_each_entry_safe(cmt_node, cmt_node_next, &cq->cmt_forest[work_id], rnode)
        {
            INIT_LIST_HEAD(&info_head);

            if (!cmt_node->valid) {
                hk_dbgv("cmt node for inode %llu is invalid, delayed deletion of this node to umount\n", cmt_node->ino);
                continue;
            }

            if (hk_grab_cmt_info(sb, cmt_node, &info_head, HK_CMT_BATCH_NUM) == 0) {
                continue;
            }

            /* Do some preprocess here */
            ///// TODO: we might check merge info here

            list_for_each_entry_safe(info, info_next, &info_head, lnode)
            {
                list_del(&info->lnode);
                hk_process_cmt_info(sb, cmt_node, info, info->type);
                schedule();
            }

            schedule();
        }
    }

    if (arg)
        kfree(arg);

    flush_signals(current);

    cmt_finished[work_id] = 1;
    wake_up_interruptible(&cmt_finish_wq);
    hk_info("cmt workers %d finished\n", work_id);
    return 0;
}

int hk_prepare_worker(struct super_block *sb, struct hk_cmt_worker_param *param, int worker_id)
{
    param->sb = sb;
    param->work_id = worker_id;
    param->name = "FUSE";

    return 0;
}

void hk_start_cmt_workers(struct super_block *sb)
{
    struct hk_cmt_worker_param *param;
    struct hk_sb_info *sbi = HK_SB(sb);
    int ret;
    int i;

    init_waitqueue_head(&cmt_finish_wq);

    for (i = 0; i < HK_CMT_WORKER_NUM; i++) {
        param = kmalloc(sizeof(struct hk_cmt_worker_param), GFP_KERNEL);

        hk_prepare_worker(sb, param, i);

        cmt_finished[i] = 0;
        sbi->cmt_workers[i] = kthread_create(hk_cmt_worker_thread,
                                             param, "hk_cmt_worker_%d", i);

        wake_up_process(sbi->cmt_workers[i]);

        hk_info("start cmt workers %d (%s)\n", i, "FUSE");
    }
}

void hk_stop_cmt_workers(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    int i;

    for (i = 0; i < HK_CMT_WORKER_NUM; i++) {
        send_sig(SIGINT, sbi->cmt_workers[i], 1);
        kthread_stop(sbi->cmt_workers[i]);
        sbi->cmt_workers[i] = NULL;
        hk_info("stop cmt worker %d (%s)\n", i, "FUSE");
    }

    wait_to_finish_cmt();

    hk_info("stop %d cmt workers\n", HK_CMT_WORKER_NUM);
}

void hk_flush_cmt_inode_queue(struct super_block *sb, struct hk_cmt_node *cmt_node)
{
    struct hk_cmt_info *info, *info_next;
    struct list_head info_head;
    int queue_len = 0;

    INIT_LIST_HEAD(&info_head);

    queue_len = hk_inf_queue_length(&cmt_node->op_q);

    if (queue_len == 0) {
        return;
    }

    hk_grab_cmt_info(sb, cmt_node, &info_head, queue_len);

    list_for_each_entry_safe(info, info_next, &info_head, lnode)
    {
        list_del(&info->lnode);
        hk_process_cmt_info(sb, cmt_node, info, info->type);
    }

    return;
}

void hk_flush_cmt_node_fast(struct super_block *sb, struct hk_cmt_node *cmt_node)
{
    struct hk_sb_info *sbi = HK_SB(sb);

    hk_flush_cmt_inode_queue(sb, cmt_node);
}

void hk_flush_cmt_queue(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_cmt_queue *cq = sbi->cq;
    struct hk_cmt_node *cmt_node, *cmt_node_next;
    struct list_head info_head;
    int i = 0, work_id = 0;

    for (work_id = 0; work_id < HK_CMT_WORKER_NUM; work_id++) {
        // for each cmt node, we flush all the operation in the queue
        rbtree_postorder_for_each_entry_safe(cmt_node, cmt_node_next, &cq->cmt_forest[work_id], rnode)
        {
            for (i = 0; i < MAX_CMT_TYPE; i++) {
                hk_flush_cmt_inode_queue(sb, cmt_node);
            }
        }
    }

    hk_info("Flush all cmt workers\n");
}

struct hk_cmt_queue *hk_init_cmt_queue(int num_workers)
{
    struct hk_cmt_queue *cq;
    int i;

    cq = kmalloc(sizeof(struct hk_cmt_queue), GFP_KERNEL);
    if (!cq) {
        hk_warn("%s: failed to allocate memory for cq\n", __func__);
        goto out;
    }

    cq->cmt_forest = kmalloc_array(num_workers, sizeof(struct rb_root), GFP_KERNEL);
    if (!cq->cmt_forest) {
        hk_warn("%s: hk_init_cmt_queue: failed to allocate memory for cmt_forest\n", __func__);
        goto out1;
    }
    for (i = 0; i < num_workers; i++) {
        cq->cmt_forest[i] = RB_ROOT;
    }

    cq->locks = kmalloc_array(num_workers, sizeof(struct mutex), GFP_KERNEL);
    if (!cq->locks) {
        hk_warn("%s: hk_init_cmt_queue: failed to allocate memory for locks\n", __func__);
        goto out2;
    }
    for (i = 0; i < num_workers; i++) {
        mutex_init(&cq->locks[i]);
    }

    return cq;

out2:
    kfree(cq);
out1:
    kfree(cq->cmt_forest);
out:
    return NULL;
}

void hk_free_cmt_queue(struct hk_cmt_queue *cq)
{
    if (cq) {
        kfree(cq->cmt_forest);
        kfree(cq->locks);
        kfree(cq);
    }
}