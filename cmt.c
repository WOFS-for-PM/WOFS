#include "hunter.h"

wait_queue_head_t cmt_finish_wq;
int cmt_finished[HK_CMT_WORKER_NUM];
int hk_request_cmt(struct super_block *sb, void *info, struct hk_inode_info_header *sih, enum hk_cmt_data_type req_type);

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
void hk_checkpoint_inode_state(struct inode *inode, struct hk_inode_state *state)
{
    state->ino = inode->i_ino;
    state->atime = inode->i_atime.tv_sec;
    state->mtime = inode->i_mtime.tv_sec;
    state->ctime = inode->i_ctime.tv_sec;
    state->size = inode->i_size;
    state->mode = inode->i_mode;
    state->uid = i_uid_read(inode);
    state->gid = i_gid_read(inode);
}

int hk_delegate_data_async(struct super_block *sb, struct inode *inode, struct hk_cmt_dbatch *batch, enum hk_cmt_data_op op)
{
    struct hk_cmt_data_info *data_info;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info_header *sih = HK_IH(inode);

    BUG_ON(batch->addr_start == 0);

    data_info = hk_alloc_hk_cmt_data_info();
    INIT_LIST_HEAD(&data_info->lnode);
    data_info->op = op;
    data_info->type = DATA;
    data_info->addr_start = batch->addr_start;
    data_info->addr_end = batch->addr_end;
    data_info->blk_start = batch->blk_start;
    data_info->blk_end = batch->blk_end;
    data_info->tstamp = get_version(sbi);

    hk_request_cmt(sb, data_info, sih, DATA);

    return 0;
}

int hk_delegate_attr_async(struct super_block *sb, struct inode *inode)
{
    struct hk_cmt_attr_info *attr_info;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info_header *sih = HK_IH(inode);

    attr_info = hk_alloc_hk_cmt_attr_info();
    INIT_LIST_HEAD(&attr_info->lnode);
    attr_info->tstamp = get_version(sbi);
    attr_info->type = ATTR;

    hk_checkpoint_inode_state(inode, &attr_info->state);

    hk_request_cmt(sb, attr_info, sih, ATTR);

    return 0;
}

int hk_delegate_jnl_async(struct super_block *sb, struct inode *inode)
{
    return -ENOTSUPP;
}

int hk_delegate_inode_async(struct super_block *sb, struct inode *inode)
{
    return -ENOTSUPP;
}

/* ===== Low-level ===== */
struct hk_cmt_node *hk_cmt_node_init(u64 ino)
{
    struct hk_cmt_node *node = hk_alloc_hk_cmt_node();

#ifdef CONFIG_DECOUPLE_WORKER
    hk_inf_queue_init(&node->data_queue);
    hk_inf_queue_init(&node->attr_queue);
    hk_inf_queue_init(&node->jnl_queue);
#else
    hk_inf_queue_init(&node->fuse_queue);
#endif
    node->ino = ino;
    node->h_addr = 0;
    node->valid = 0;
    node->cmt_inode = NULL;

    return node;
}

void hk_cmt_node_destroy(struct hk_cmt_node *node)
{
    if (node) {
        hk_free_hk_cmt_node(node);
    }
}

void hk_cmt_info_destroy_wo_data(void *cmt_info)
{
    struct hk_cmt_common_info *common_info = cmt_info;
    switch (common_info->type) {
    case DATA:
        break;
    case ATTR:
        hk_free_hk_cmt_attr_info((struct hk_cmt_attr_info *)common_info);
        break;
    case JNL:
        hk_free_hk_cmt_jnl_info((struct hk_cmt_jnl_info *)common_info);
        break;
    case INODE:
        hk_free_hk_cmt_inode_info((struct hk_cmt_inode_info *)common_info);
        break;
    default:
        break;
    }
}

void hk_cmt_info_destroy(void *cmt_info)
{
    struct hk_cmt_common_info *common_info = cmt_info;
    switch (common_info->type) {
    case DATA:
        hk_free_hk_cmt_data_info((struct hk_cmt_data_info *)common_info);
        break;
    case ATTR:
    case JNL:
    case INODE:
        hk_cmt_info_destroy_wo_data(cmt_info);
        break;
    default:
        break;
    }
}

void hk_invalidate_delegated_info_callback(void *node)
{
    struct hk_cmt_common_info *common_info = node;

    switch (common_info->type) {
    case DATA: {
        u8 op = ((struct hk_cmt_data_info *)common_info)->op;
        if (op == CMT_VALID)
            ((struct hk_cmt_data_info *)common_info)->op = CMT_DELETED_VALID;
        else if (op == CMT_INVALID)
            ((struct hk_cmt_data_info *)common_info)->op = CMT_DELETED_INVALID;
        break;
    }
    default:
        break;
    }
}

void hk_cmt_node_clean(struct hk_cmt_node *node)
{
    if (node) {
#ifdef CONFIG_DECOUPLE_WORKER
        hk_inf_queue_modify(&node->data_queue, hk_invalidate_delegated_info_callback);
        hk_inf_queue_destory(&node->attr_queue, hk_cmt_info_destroy);
        hk_inf_queue_destory(&node->jnl_queue, hk_cmt_info_destroy);
        if (node->cmt_inode) {
            hk_cmt_info_destroy(node->cmt_inode);
            node->cmt_inode = NULL;
        }
#else
        hk_inf_queue_modify(&node->fuse_queue, hk_invalidate_delegated_info_callback);
        hk_inf_queue_destory(&node->fuse_queue, hk_cmt_info_destroy_wo_data);
#endif
    }
}

int hk_cmt_manage_node(struct super_block *sb, struct hk_cmt_node *cmt_node, struct hk_cmt_node **exist)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_cmt_queue *cq = sbi->cq;
    struct rb_root *tree = &cq->cmt_tree;
    struct hk_cmt_node *curr;
    struct rb_node **temp, *parent;
    int compVal;

    temp = &(tree->rb_node);
    parent = NULL;

    mutex_lock(&cq->lock);

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
                mutex_unlock(&cq->lock);
                return -EINVAL;
            } else {
                curr->valid = 1;
                if (exist) {
                    *exist = curr;
                }
                hk_dbg("find an invalidated slot for request %llu to reuse\n", cmt_node->ino);
                mutex_unlock(&cq->lock);
                return -EEXIST;
            }
        }
    }

    rb_link_node(&cmt_node->rnode, parent, temp);
    rb_insert_color(&cmt_node->rnode, tree);

    if (exist) {
        *exist = NULL;
    }

    mutex_unlock(&cq->lock);

    return 0;
}

struct hk_cmt_node *hk_cmt_search_node(struct super_block *sb, u64 ino)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_cmt_queue *cq = sbi->cq;
    struct rb_root *tree = &cq->cmt_tree;
    struct hk_cmt_node *curr;
    struct rb_node **temp, *parent;
    int compVal;

    temp = &(tree->rb_node);
    parent = NULL;

    mutex_lock(&cq->lock);

    while (*temp) {
        curr = container_of(*temp, struct hk_cmt_node, rnode);
        compVal = curr->ino > ino ? -1 : (curr->ino < ino ? 1 : 0);
        parent = *temp;

        if (compVal == -1) {
            temp = &((*temp)->rb_left);
        } else if (compVal == 1) {
            temp = &((*temp)->rb_right);
        } else {
            mutex_unlock(&cq->lock);
            return curr;
        }
    }
    mutex_unlock(&cq->lock);

    return NULL;
}

int hk_cmt_unmanage_node(struct super_block *sb, u64 ino)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_cmt_queue *cq = sbi->cq;
    struct rb_root *tree = &cq->cmt_tree;
    struct hk_cmt_node *curr;
    struct rb_node **temp, *parent;
    int compVal;

    temp = &(tree->rb_node);
    parent = NULL;

    mutex_lock(&cq->lock);

    while (*temp) {
        curr = container_of(*temp, struct hk_cmt_node, rnode);
        compVal = curr->ino > ino ? -1 : (curr->ino < ino ? 1 : 0);
        parent = *temp;

        if (compVal == -1) {
            temp = &((*temp)->rb_left);
        } else if (compVal == 1) {
            temp = &((*temp)->rb_right);
        } else {
            // NOTE: we cannot free the node here, because background worker might hold this.
            // FIXME: how to free the node?
            curr = container_of(*temp, struct hk_cmt_node, rnode);
            curr->valid = 0;
            hk_cmt_node_clean(curr);
            mutex_unlock(&cq->lock);
            return 0;
        }
    }

    mutex_unlock(&cq->lock);

    return -EINVAL;
}

void hk_cmt_destroy_node_tree(struct super_block *sb, struct rb_root *tree)
{
    struct hk_cmt_node *curr;
    struct rb_node *temp;

    temp = rb_first(tree);
    while (temp) {
        curr = container_of(temp, struct hk_cmt_node, rnode);
        temp = rb_next(temp);
        rb_erase(&curr->rnode, tree);

#ifdef CONFIG_DECOUPLE_WORKER
        HK_ASSERT(hk_inf_queue_length(&curr->data_queue) == 0);
        HK_ASSERT(hk_inf_queue_length(&curr->attr_queue) == 0);
        HK_ASSERT(hk_inf_queue_length(&curr->jnl_queue) == 0);
        HK_ASSERT(curr->cmt_inode == NULL);
#else
        HK_ASSERT(hk_inf_queue_length(&curr->fuse_queue) == 0);
#endif

        hk_cmt_node_destroy(curr);
    }
}

int hk_request_cmt(struct super_block *sb, void *info, struct hk_inode_info_header *sih, enum hk_cmt_data_type req_type)
{
#ifdef CONFIG_DECOUPLE_WORKER
    switch (req_type) {
    case DATA: {
        struct hk_cmt_data_info *cmt_data = (struct hk_cmt_data_info *)info;
        hk_inf_queue_add_tail_locked(&sih->cmt_node->data_queue, &cmt_data->lnode);
        break;
    }
    case ATTR: {
        struct hk_cmt_attr_info *cmt_attr = (struct hk_cmt_attr_info *)info;
        hk_inf_queue_add_tail_locked(&sih->cmt_node->attr_queue, &cmt_attr->lnode);
        break;
    }
    case JNL: {
        struct hk_cmt_jnl_info *cmt_jnl = (struct hk_cmt_jnl_info *)info;
        hk_inf_queue_add_tail_locked(&sih->cmt_node->jnl_queue, &cmt_jnl->lnode);
        break;
    }
    case INODE:
        // reader can not access the inode until the cmt_inode is finished value assignment.
        WRITE_ONCE(sih->cmt_node->cmt_inode, (struct hk_cmt_inode_info *)info);
        break;
    default:
        break;
    }
#else
    struct hk_cmt_common_info *cmt_info = (struct hk_cmt_common_info *)info;
    hk_inf_queue_add_tail_locked(&sih->cmt_node->fuse_queue, &cmt_info->lnode);
#endif
    return 0;
}

int hk_grab_cmt_info(struct super_block *sb, struct hk_cmt_node *cmt_node, void *info_head, int type, int batch_num)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    int ret = 0;

#ifdef CONFIG_DECOUPLE_WORKER
    switch (type) {
    case DATA:
        ret = hk_inf_queue_try_pop_front_batch_locked(&cmt_node->data_queue, info_head, batch_num);
        break;
    case ATTR:
        ret = hk_inf_queue_try_pop_front_batch_locked(&cmt_node->attr_queue, info_head, batch_num);
        break;
    case JNL:
        ret = hk_inf_queue_try_pop_front_batch_locked(&cmt_node->jnl_queue, info_head, batch_num);
        break;
    case INODE:
        (void)batch_num;
        if (cmt_node->cmt_inode != NULL) {
            info_head = cmt_node->cmt_inode;
            cmt_node->cmt_inode = NULL;
        }
        break;
    default:
        BUG_ON(1);
        break;
    }
#else
    ret = hk_inf_queue_try_pop_front_batch_locked(&cmt_node->fuse_queue, info_head, batch_num);
#endif
    return ret;
}

int hk_process_data_info(struct super_block *sb, u64 ino, struct hk_cmt_data_info *data_info)
{
    struct hk_header *hdr;
    struct hk_layout_info *layout = NULL;
    u64 addr, blk, index;
    u64 addr_start = data_info->addr_start;
    u64 addr_end = data_info->addr_end;
    u64 blk_start = data_info->blk_start;
    u64 blk_end = data_info->blk_end;

    hdr = sm_get_hdr_by_addr(sb, addr_start);
    layout = sm_get_layout_by_hdr(sb, hdr);
    use_layout(layout);
    for (addr = addr_start, blk = blk_start; addr < addr_end; addr += HK_PBLK_SZ, blk += 1) {
        hdr = sm_get_hdr_by_addr(sb, addr);
        switch (data_info->op) {
        case CMT_VALID: {
            sm_valid_data_sync(sb, addr, ino, blk, data_info->tstamp);
            break;
        }
        case CMT_INVALID: {
            if (hdr->tstamp <= data_info->tstamp) {
                sm_invalid_data_sync(sb, addr, ino);
            } else {
                BUG_ON(1);
            }
            break;
        }
        case CMT_DELETED_VALID:
        case CMT_DELETED_INVALID:
            // NOTE: merge redundant deleted commition.
            //       In-PM hdr shall be valid or never written.
            //       If it is invalidated, there will be no
            //       CMT_DELETED_VALID/INVALID
            if (hdr->valid != 0)
                sm_delete_data_sync(sb, addr, ino, data_info->op);
        default:
            break;
        }
    }
    unuse_layout(layout);
}

int hk_process_attr_info(struct super_block *sb, u64 ino, struct hk_cmt_attr_info *cmt_attr)
{
    struct hk_inode_state *state = NULL;

    state = &cmt_attr->state;
    hk_commit_inode_checkpoint(sb, state);
    return 0;
}

int hk_process_jnl_info(struct super_block *sb, u64 ino, struct hk_cmt_jnl_info *cmt_jnl)
{
    // TODO
    return 0;
}

int hk_process_inode_info(struct super_block *sb, u64 ino, struct hk_cmt_inode_info *cmt_inode)
{
    // TODO
    return 0;
}

int hk_process_cmt_info(struct super_block *sb, u64 ino, void *info, int type)
{
    switch (type) {
    case DATA:
        hk_process_data_info(sb, ino, (struct hk_cmt_data_info *)info);
        break;
    case ATTR:
        hk_process_attr_info(sb, ino, (struct hk_cmt_attr_info *)info);
        break;
    case JNL:
        hk_process_jnl_info(sb, ino, (struct hk_cmt_jnl_info *)info);
        break;
    case INODE:
        hk_process_inode_info(sb, ino, (struct hk_cmt_inode_info *)info);
        break;
    default:
        break;
    }

    hk_cmt_info_destroy(info);

    return 0;
}

/* == Worker == */
struct hk_cmt_worker_param {
    struct super_block *sb;
    int work_id;
#ifdef CONFIG_DECOUPLE_WORKER
    int work_type;
#endif
    const char *name;
};

static int hk_cmt_worker_thread(void *arg)
{
    struct hk_cmt_worker_param *param = (struct hk_cmt_worker_param *)arg;
    struct super_block *sb = param->sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    int work_id = param->work_id;
    enum hk_cmt_data_type work_type = DATA;

#ifdef CONFIG_DECOUPLE_WORKER
    work_type = param->work_type;
#endif

    allow_signal(SIGINT);

    struct hk_cmt_queue *cq = sbi->cq;
    struct hk_cmt_node *cmt_node, *cmt_node_next;
    struct hk_cmt_common_info *info, *info_next;
    struct list_head info_head;

    while (!kthread_should_stop()) {
        ssleep_interruptible(HK_CMT_TIME_GAP);

        rbtree_postorder_for_each_entry_safe(cmt_node, cmt_node_next, &cq->cmt_tree, rnode)
        {
            INIT_LIST_HEAD(&info_head);

            if (!cmt_node->valid) {
                hk_dbgv("cmt node for inode %llu is invalid, delayed deletion of this node to umount\n", cmt_node->ino);
                continue;
            }

            if (hk_grab_cmt_info(sb, cmt_node, &info_head, work_type, HK_CMT_BATCH_NUM) == 0) {
                continue;
            }

            /* Do some preprocess here */
            // TODO: we might check merge info here

            list_for_each_entry_safe(info, info_next, &info_head, lnode)
            {
                list_del(&info->lnode);
                hk_process_cmt_info(sb, cmt_node->ino, info, info->type);
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

static inline const char *worker_type_id_to_str(int work_id)
{
    switch (work_id) {
    case DATA:
        return "DATA";
    case ATTR:
        return "ATTR";
    case JNL:
        return "JNL";
    case INODE:
        return "INODE";
    default:
        return "UNKNOWN";
    }
}

int hk_prepare_worker(struct super_block *sb, struct hk_cmt_worker_param *param, int worker_id)
{
    param->sb = sb;
    param->work_id = worker_id;

#ifdef CONFIG_DECOUPLE_WORKER
    enum hk_cmt_data_type work_type = worker_id;
    param->work_type = work_type;
    param->name = worker_type_id_to_str(work_type);
#else
    param->name = "FUSE";
#endif

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

#ifdef CONFIG_DECOUPLE_WORKER
        hk_info("start cmt workers %d (%s)\n", i, param->name);
#else
        hk_info("start cmt workers %d (%s)\n", i, "FUSE");
#endif
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
#ifdef CONFIG_DECOUPLE_WORKER
        hk_info("stop cmt worker %d (%s)\n", i, worker_type_id_to_str(i));
#else
        hk_info("stop cmt worker %d (%s)\n", i, "FUSE");
#endif
    }

    wait_to_finish_cmt();

    hk_info("stop %d cmt workers\n", HK_CMT_WORKER_NUM);
}

void hk_flush_cmt_inode_queue(struct super_block *sb, struct hk_cmt_node *cmt_node, enum hk_cmt_data_type type)
{
    struct hk_cmt_common_info *info, *info_next;
    struct list_head info_head;
    int queue_len = 0;

    INIT_LIST_HEAD(&info_head);

#ifdef CONFIG_DECOUPLE_WORKER
    switch (type) {
    case DATA:
        queue_len = hk_inf_queue_length(&cmt_node->data_queue);
        break;
    case ATTR:
        queue_len = hk_inf_queue_length(&cmt_node->attr_queue);
        break;
    case JNL:
        queue_len = hk_inf_queue_length(&cmt_node->jnl_queue);
        break;
    case INODE:
        queue_len = 1;
        break;
    default:
        break;
    }
#else
    queue_len = hk_inf_queue_length(&cmt_node->fuse_queue);
#endif

    if (queue_len == 0) {
        return;
    }

    hk_grab_cmt_info(sb, cmt_node, &info_head, type, queue_len);

    list_for_each_entry_safe(info, info_next, &info_head, lnode)
    {
        list_del(&info->lnode);
        hk_process_cmt_info(sb, cmt_node->ino, info, info->type);
    }

    return;
}

void hk_flush_cmt_node_fast(struct super_block *sb, struct hk_cmt_node *cmt_node)
{
    struct hk_sb_info *sbi = HK_SB(sb);
#ifdef CONFIG_DECOUPLE_WORKER
    hk_flush_cmt_inode_queue(sb, cmt_node, DATA);
    hk_flush_cmt_inode_queue(sb, cmt_node, ATTR);
    hk_flush_cmt_inode_queue(sb, cmt_node, JNL);
    hk_flush_cmt_inode_queue(sb, cmt_node, INODE);
#else
    hk_flush_cmt_inode_queue(sb, cmt_node, MAX_CMT_TYPE);
#endif
}

void hk_flush_cmt_queue(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_cmt_queue *cq = sbi->cq;
    struct hk_cmt_node *cmt_node, *cmt_node_next;
    struct list_head info_head;
    enum hk_cmt_data_type work_types[MAX_CMT_TYPE] = {DATA, ATTR, JNL, INODE};
    int i = 0;

    // for each cmt node, we flush all the data, attr, jnl, inode info in the queue
    rbtree_postorder_for_each_entry_safe(cmt_node, cmt_node_next, &cq->cmt_tree, rnode)
    {
        for (i = 0; i < MAX_CMT_TYPE; i++) {
            hk_flush_cmt_inode_queue(sb, cmt_node, work_types[i]);
        }
    }

    hk_info("Flush all cmt workers\n");
}

struct hk_cmt_queue *hk_init_cmt_queue(void)
{
    struct hk_cmt_queue *cq;
    int i;

    cq = kmalloc(sizeof(struct hk_cmt_queue), GFP_KERNEL);

    if (!cq) {
        hk_warn("hk_init_cmt_queue: failed to allocate memory for cq\n");
        return NULL;
    }

    cq->cmt_tree = RB_ROOT;
    mutex_init(&cq->lock);

    return cq;
}

void hk_free_cmt_queue(struct hk_cmt_queue *cq)
{
    if (cq) {
        kfree(cq);
    }
}