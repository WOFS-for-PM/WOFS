#include "hunter.h"

#define get_fetcher(cq, i) ((struct memory_fetcher *)((cq)->fetchers + (i) * sizeof(struct memory_fetcher)))

struct pre_alloc_memory_pool_control_msg {
    struct super_block *sb;
};

struct pre_alloc_memory_pool {
    struct pre_alloc_memory_pool_control_msg ctl_msg;
    struct list_head memory_node_list;
    spinlock_t lock;
    struct list_head prepare_node_list;
    void *pool[1024 * 1024 * 16];
    unsigned long cur_alloc;
    size_t size;
    int batch;
    int count;
    void *(*memory_alloc)(void *, size_t, gfp_t);
    void (*memory_free)(void *, void *);
};

struct memory_node {
    struct list_head node;
    void *memory;
};

struct memory_fetcher {
    struct pre_alloc_memory_pool pamp;
    struct task_struct *mem_fetcher_thread;
};

static void *alloc_cmt_info(void *ctl_msg, size_t size, gfp_t flags)
{
    struct pre_alloc_memory_pool_control_msg *msg = ctl_msg;
    return hk_alloc_cmt_info(msg->sb);
}

static void free_cmt_info(void *ctl_msg, void *node)
{
    (void) ctl_msg;
    hk_free_cmt_info(node);
}

static int destroy_memory_node_list(struct pre_alloc_memory_pool *pamp, struct list_head *head)
{
    struct memory_node *cur;
    struct list_head *pos;
    struct list_head *n;

    list_for_each_safe(pos, n, head)
    {
        cur = list_entry(pos, struct memory_node, node);
        list_del(pos);
        
        if (pamp->memory_free != NULL) {
            pamp->memory_free(&pamp->ctl_msg, cur->memory);
        } else {
            kfree(cur->memory);
        }
        kfree(cur);
    }
}

static int destroy_pre_alloc_memory_pool(struct pre_alloc_memory_pool *pamp)
{
    // destroy_memory_node_list(pamp, &pamp->memory_node_list);
    // destroy_memory_node_list(pamp, &pamp->prepare_node_list);
    int i;
    for (i = pamp->cur_alloc; i < 1024 * 1024 * 16; i++) {
        if (pamp->pool[i] != NULL) {
            if (pamp->memory_free != NULL) {
                pamp->memory_free(&pamp->ctl_msg, pamp->pool[i]);
            } else {
                kfree(pamp->pool[i]);
            }
        }
    }
    return 0;
}

static __always_inline void *get_pre_alloc_memory(struct super_block *sb, struct hk_cmt_queue *cq)
{
    struct memory_node *cur;
    struct list_head *pos;
    void *memory = NULL;
    int fetcher_id = 0;
    struct pre_alloc_memory_pool *pamp = &get_fetcher(cq, fetcher_id)->pamp;

    spin_lock(&pamp->lock);
    // list_for_each(pos, &pamp->memory_node_list)
    // {
    //     cur = list_entry(pos, struct memory_node, node);
    //     list_del(pos);
    //     kfree(cur);
    //     pamp->count--;
    //     memory = cur->memory;
    //     break;
    // }
    if (pamp->cur_alloc != 1024 * 1024 * 16) {
        memory = pamp->pool[pamp->cur_alloc++];
    }
    spin_unlock(&pamp->lock);
    return memory;
}

static int link_prepare_node_list_to_useable(struct pre_alloc_memory_pool *pamp, size_t count)
{
    spin_lock(&pamp->lock);
    list_splice(&pamp->prepare_node_list, &pamp->memory_node_list);
    pamp->count += count;
    spin_unlock(&pamp->lock);
    /* reinit list */
    INIT_LIST_HEAD(&pamp->prepare_node_list);
    return 0;
}

static int populate_pre_alloc_memory_pool(struct pre_alloc_memory_pool *pamp, size_t count)
{
    struct memory_node *cur;
    int i;
    hk_info("populate_pre_alloc_memory_pool count %d");
    
    for (i = 0; i < count; i++) {
        void *memory;
        if (pamp->memory_alloc != NULL) {
            memory = pamp->memory_alloc(&pamp->ctl_msg, pamp->size, GFP_KERNEL);
        } else {
            memory = kmalloc(pamp->size, GFP_KERNEL);
        }
        if (memory == NULL) {
            hk_warn("kmalloc memory failed");
            return -1;
        }
        pamp->pool[i] = memory;
    }
    
    // for (i = 0; i < count; i++) {
    //     cur = kmalloc(sizeof(struct memory_node), GFP_KERNEL);
    //     if (cur == NULL) {
    //         return -1;
    //     }
    //     if (pamp->memory_alloc != NULL) {
    //         cur->memory = pamp->memory_alloc(&pamp->ctl_msg, pamp->size, GFP_KERNEL);
    //     } else {
    //         cur->memory = kmalloc(pamp->size, GFP_KERNEL);
    //     }
    //     if (cur->memory == NULL) {
    //         kfree(cur);
    //         return -1;
    //     }
    //     list_add_tail(&cur->node, &pamp->prepare_node_list);
    //     pamp->count++;
    // }
    // link_prepare_node_list_to_useable(pamp, count);
    return 0;
}

static int init_pre_alloc_memory_pool(struct super_block *sb,
                                      struct pre_alloc_memory_pool *pamp,
                                      size_t size, size_t batch,
                                      void *(*memory_alloc)(void *, size_t, gfp_t), 
                                      void (*memory_free)(void *, void *))
{
    pamp->ctl_msg.sb = sb;
    pamp->size = size;
    pamp->batch = batch;
    pamp->count = 0;
    pamp->memory_alloc = memory_alloc;
    pamp->memory_free = memory_free;
    spin_lock_init(&pamp->lock);
    pamp->cur_alloc = 0;
    // INIT_LIST_HEAD(&pamp->memory_node_list);
    // INIT_LIST_HEAD(&pamp->prepare_node_list);
    if (populate_pre_alloc_memory_pool(pamp, batch) != 0) {
        destroy_pre_alloc_memory_pool(pamp);
        return -1;
    }
    return 0;
}

static int try_to_populate_memory(struct pre_alloc_memory_pool *pamp)
{
    if (pamp->count < (pamp->batch / 2)) {
        if (populate_pre_alloc_memory_pool(pamp, pamp->batch / 4) != 0) {
            return -1;
        }
    }
    return 0;
}

int hk_request_cmt(struct super_block *sb, struct hk_cmt_info *info)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_cmt_queue *cq = sbi->cq;
    u64 ino;
    int key;

    ino = info->ino;

    key = hash_min(ino, HK_CMT_QUEUE_BITS);

    spin_lock(&cq->locks[key]);
    cq->nitems[key]++;
    chash_add_head(cq->table, &info->slot, key);
    spin_unlock(&cq->locks[key]);

    return 0;
}

int hk_valid_hdr_background(struct super_block *sb, struct inode *inode, u64 blk_addr, u64 f_blk)
{
    struct hk_cmt_info *info;
    struct hk_sb_info *sbi = HK_SB(sb);

    INIT_TIMING(request_time);
    INIT_TIMING(prepare_time);
    HK_START_TIMING(request_valid_t, request_time);

    HK_START_TIMING(prepare_request_t, prepare_time);
    info = hk_alloc_cmt_info(sb);
    
    info->type = CMT_VALID;
    info->ino = inode->i_ino;
    info->addr_start = blk_addr;
    info->addr_end = blk_addr + HK_PBLK_SZ(sbi);
    info->blk_start = f_blk;
    info->tstamp = get_version(sbi);
    info->uid = i_uid_read(inode);
    info->gid = i_gid_read(inode);
    info->mode = inode->i_mode;
    info->time = inode->i_mtime.tv_sec;
    info->size = inode->i_size;
    HK_END_TIMING(prepare_request_t, prepare_time);

    hk_request_cmt(sb, info);
    HK_END_TIMING(request_valid_t, request_time);

    return 0;
}

int hk_invalid_hdr_background(struct super_block *sb, struct inode *inode, u64 blk_addr, u64 f_blk)
{
    struct hk_cmt_info *info;
    struct hk_sb_info *sbi = HK_SB(sb);
    int pamp_id = hk_get_cpuid(sb) % HK_CMT_WORKER_NUM;

    INIT_TIMING(request_time);
    INIT_TIMING(prepare_time);
    HK_START_TIMING(request_valid_t, request_time);

    HK_START_TIMING(prepare_request_t, prepare_time);

    info = hk_alloc_cmt_info(sb);
    info->type = CMT_INVALID;
    info->ino = inode->i_ino;
    info->addr_start = blk_addr;
    info->addr_end = blk_addr + HK_PBLK_SZ(sbi);
    info->blk_start = f_blk;
    info->tstamp = get_version(sbi);
    info->uid = i_uid_read(inode);
    info->gid = i_gid_read(inode);
    info->mode = inode->i_mode;
    info->time = inode->i_mtime.tv_sec;
    info->size = inode->i_size;

    HK_END_TIMING(prepare_request_t, prepare_time);
    
    hk_request_cmt(sb, info);

    HK_END_TIMING(request_invalid_t, request_time);
    return 0;
}

int hk_valid_range_background(struct super_block *sb, struct inode *inode, struct hk_cmt_batch *batch)
{
    struct hk_cmt_info *info;
    struct hk_sb_info *sbi = HK_SB(sb);

    INIT_TIMING(request_time);
    INIT_TIMING(prepare_time);
    HK_START_TIMING(request_valid_t, request_time);
    HK_START_TIMING(prepare_request_t, prepare_time);
    
    info = hk_alloc_cmt_info(sb);
    info->type = CMT_VALID;
    info->ino = inode->i_ino;
    info->addr_start = batch->addr_start;
    info->addr_end = batch->addr_end;
    info->blk_start = batch->blk_start;
    info->tstamp = get_version(sbi);
    info->uid = i_uid_read(inode);
    info->gid = i_gid_read(inode);
    info->mode = inode->i_mode;
    info->time = inode->i_mtime.tv_sec;
    info->size = inode->i_size;

    HK_END_TIMING(prepare_request_t, prepare_time);

    hk_request_cmt(sb, info);
    HK_END_TIMING(request_valid_t, request_time);
    return 0;
}

struct hk_cmt_info *hk_grab_cmt_info(struct super_block *sb, int key)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_cmt_queue *cq = sbi->cq;
    struct hk_cmt_info *info = NULL;
    struct ch_slot *slot;

    slot = chash_last(cq->table, key);
    if (chash_is_sentinal(cq->table, key, slot)) {
        goto out;
    }
    info = chlist_entry(slot, struct hk_cmt_info, slot);
    chash_del(&info->slot);
out:
    if (info) {
        cq->nitems[key]--;
    }
    return info;
}

int hk_process_single_cmt_info(struct super_block *sb, struct hk_cmt_info *info)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_header *hdr, *hdr_traverse;
    struct hk_inode *pi;
    struct hk_inode_state state;
    struct hk_layout_info *layout = NULL, *layout_migrated = NULL;
    u64 addr, blk, addr_migrated;
    u64 ino = info->ino;
    u64 addr_start = info->addr_start;
    u64 addr_end = info->addr_end;
    u64 blk_start = info->blk_start;

    hdr = sm_get_hdr_by_addr(sb, addr_start);
    layout = sm_get_layout_by_hdr(sb, hdr);

    use_nvm_inode(sb, ino);
    pi = hk_get_inode_by_ino(sb, ino);
    for (addr = addr_start, blk = blk_start; addr < addr_end; addr += HK_PBLK_SZ(sbi), blk += 1) {
        hdr = sm_get_hdr_by_addr(sb, addr);
        switch (info->type) {
        case CMT_VALID: {
            sm_valid_hdr(sb, addr, ino, blk, info->tstamp);
            break;
        }
        case CMT_INVALID: {
            /* We must handle two exception here
               1. The target hdr is valid, but newer than the process info
               2. The target hdr is invalid
               - The first situation could be caused by equliazer migration process.
               - The second situation could only be equliazer migration process, or truncate process
            */
            if ((hdr->valid && hdr->tstamp > info->tstamp) ||
                (!hdr->valid)) {
                hk_dbgv("hdr is migrated, in-NVM ver: %llu, in-Fly ver: %llu, valid: %d\n",
                        hdr->tstamp, info->tstamp, hdr->valid);
                traverse_inode_hdr(sbi, pi, hdr_traverse)
                {
                    /* We must ensure that no any invalidator is running at this time */
                    if (blk == hdr_traverse->f_blk && hdr_traverse->valid) {
                        addr_migrated = sm_get_addr_by_hdr(sb, hdr_traverse);
                        layout = sm_get_layout_by_hdr(sb, (u64)hdr);
                        layout_migrated = sm_get_layout_by_hdr(sb, hdr_traverse);

                        hk_dbgv("hdr has been migrated: request at %llu in %d, newest at %llu in %d\n", hk_get_dblk_by_addr(sbi, addr), layout->cpuid, hk_get_dblk_by_addr(sbi, addr_migrated), layout_migrated->cpuid);
                        /* Note that the situation below will not happen in GC-Mechnism workload. */
                        /* We must handle the situation that (Note that A and B is in the same layout)):
                            1. The target block (B) is invalid, and is migrated to a newly place A.
                            2. A is then invalid by a foreground request: i.e. a new cmt request to invalid A is sent to the cmt queue.
                            3. A is then invalided by Step 1, because we find that B is invalid.
                            4. The request to invalid A is grabed, and finds that A is already invalid (see Step 3). So the cmt request in Step 2 is satisfied, we should normally drop it.
                         */
                        if (layout->cpuid == layout_migrated->cpuid) {
                            if (addr_migrated < addr) {
                                sm_invalid_hdr(sb, addr_migrated, ino);
                            }
                        }
                    }
                }
            } else if (hdr->tstamp <= info->tstamp) {
                sm_invalid_hdr(sb, addr, ino);
            } else {
                BUG_ON(1);
            }
            break;
        }
        default:
            break;
        }
    }

    state.ino = ino;
    state.atime = state.ctime = state.mtime = info->time;
    state.uid = info->uid;
    state.gid = info->gid;
    state.mode = info->mode;
    state.size = info->size;

    hk_commit_inode_state(sb, &state);

    unuse_nvm_inode(sb, ino);

    hk_free_cmt_info(info);

    return 0;
}

u64 hk_get_nitems_in_cq_roughly(struct hk_cmt_queue *cq, int key)
{
    return cq->nitems[key];
}

struct hk_cmt_worker_param {
    struct super_block *sb;
    int work_id;
};

static int hk_cmt_worker_thread(void *arg)
{
    struct hk_cmt_worker_param *param = (struct hk_cmt_worker_param *)arg;
    struct super_block *sb = param->sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_cmt_info *info;
    int work_id = param->work_id;
    int key, start_key, end_key;
    int batch;

    start_key = work_id * (1 << HK_CMT_QUEUE_BITS) / HK_CMT_WORKER_NUM;
    end_key = (work_id + 1) * (1 << HK_CMT_QUEUE_BITS) / HK_CMT_WORKER_NUM;

    allow_signal(SIGABRT);

    for (;;) {
    again:
        ssleep_interruptible(sbi->wake_up_interval);

        if (kthread_should_stop())
            break;

        batch = 0;
        for (key = start_key; key < end_key; key++) {
            /* NOTE: single lock-free consumer: make sure the number
                     items is more than per process pass */
            if (hk_get_nitems_in_cq_roughly(sbi->cq, key) >= HK_CMT_WAKEUP_THRESHOLD) {
                while ((info = hk_grab_cmt_info(sb, key)) != NULL) {
                    hk_process_single_cmt_info(sb, info);
                    batch++;
                    if (batch >= HK_CMT_MAX_PROCESS_BATCH) {
                        goto again;
                    }
                    schedule();
                }
            }
        }
    }

    flush_signals(current);

    if (arg)
        kfree(arg);

    hk_info("cmt workers %d finished\n", work_id);
    return 0;
}

void hk_start_cmt_workers(struct super_block *sb)
{
    struct hk_cmt_worker_param *param;
    struct hk_sb_info *sbi = HK_SB(sb);
    int i;

    for (i = 0; i < HK_CMT_WORKER_NUM; i++) {
        param = kmalloc(sizeof(struct hk_cmt_worker_param), GFP_KERNEL);
        param->sb = sb;
        param->work_id = i;

        sbi->cmt_workers[i] = kthread_create(hk_cmt_worker_thread,
                                             param, "hk_cmt_worker_%d", i);
        wake_up_process(sbi->cmt_workers[i]);
        hk_info("start cmt workers %d\n", i);
    }
    hk_info("Each worker wakes up every %d s\n", sbi->wake_up_interval);
}

void hk_stop_cmt_workers(struct super_block *sb)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    int i;

    for (i = 0; i < HK_CMT_WORKER_NUM; i++) {
        send_sig_info(SIGABRT, SEND_SIG_NOINFO, sbi->cmt_workers[i]);
        kthread_stop(sbi->cmt_workers[i]);
        sbi->cmt_workers[i] = NULL;
    }

    hk_info("stop %d cmt workers\n", HK_CMT_WORKER_NUM);
}

void hk_flush_cmt_inode_fast(struct super_block *sb, u64 ino)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_cmt_queue *cq = sbi->cq;
    struct hk_cmt_info *info;
    struct ch_slot *slot;
    struct ch_slot *slot_prev;
    int key;

    key = hash_min(ino, HK_CMT_QUEUE_BITS);

    spin_lock(&cq->locks[key]);
    slot = chash_last(cq->table, key);
    while (!chash_is_sentinal(cq->table, key, slot)) {
        info = chlist_entry(slot, struct hk_cmt_info, slot);
        slot_prev = slot->prev;
        if (info->ino == ino) {
            chash_del(&info->slot);
            hk_process_single_cmt_info(sb, info);
        }
        slot = slot_prev;
    }
    spin_unlock(&cq->locks[key]);
}

void hk_flush_cmt_queue(struct super_block *sb)
{
    struct hk_cmt_info *info;
    int key;

    for (key = 0; key < (1 << HK_CMT_QUEUE_BITS); key++) {
        while ((info = hk_grab_cmt_info(sb, key)) != NULL) {
            hk_process_single_cmt_info(sb, info);
            schedule();
        }
    }
    hk_info("flush all cmt workers\n");
}

struct hk_memory_fetcher_param {
    struct hk_cmt_queue *cq;
    int fetcher_id;
};

static int hk_memory_fetcher_thread(void *arg) 
{
    struct hk_memory_fetcher_param *param = (struct hk_memory_fetcher_param *)arg;
    int fetcher_id = param->fetcher_id;
    struct hk_cmt_queue *cq = param->cq;

    while (true) {
        if (kthread_should_stop())
            break;
        try_to_populate_memory(&get_fetcher(cq, fetcher_id)->pamp);
        schedule_timeout(100);
    }

    if (arg)
        kfree(arg);
    hk_info("memory fetcher %d finished\n", fetcher_id);
}

void hk_start_memory_fetchers(struct hk_cmt_queue *cq)
{
    struct hk_memory_fetcher_param *param;
    int i;

    for (i = 0; i < cq->nfetchers; i++) {
        param = kmalloc(sizeof(struct hk_memory_fetcher_param), GFP_KERNEL);
        param->cq = cq;
        param->fetcher_id = i;

        get_fetcher(cq, i)->mem_fetcher_thread = kthread_create(hk_memory_fetcher_thread,
                                                                param, 
                                                                "hk_fetcher_worker_%d", i);

        wake_up_process(get_fetcher(cq, i)->mem_fetcher_thread);
        hk_info("start fetcher %d\n", i);
    }
}

void hk_stop_memory_fetchers(struct hk_cmt_queue *cq)
{
    int i;

    for (i = 0; i < cq->nfetchers; i++) {
        kthread_stop(get_fetcher(cq, i)->mem_fetcher_thread);
        get_fetcher(cq, i)->mem_fetcher_thread = NULL;
    }

    hk_info("stop %d fetchers\n", cq->nfetchers);
}

struct hk_cmt_queue *hk_init_cmt_queue(struct super_block *sb, int nfecthers)
{
    struct hk_cmt_queue *cq;
    int i;

    cq = kmalloc(sizeof(struct hk_cmt_queue), GFP_KERNEL);
    if (!cq) {
        hk_warn("hk_init_cmt_queue: failed to allocate memory for cq\n");
        return NULL;
    }

    chash_init(cq->table, HK_CMT_QUEUE_BITS);

    for (i = 0; i < (1 << HK_CMT_QUEUE_BITS); i++) {
        spin_lock_init(&cq->locks[i]);
        cq->nitems[i] = 0;
    }
    
    // cq->nfetchers = nfecthers;
    // cq->fetchers = kvmalloc(sizeof(struct memory_fetcher) * nfecthers, GFP_KERNEL);
    // if (!cq->fetchers) {
    //     hk_warn("hk_init_cmt_queue: failed to allocate memory for fetchers\n");
    //     return NULL;
    // }

    // for (i = 0; i < nfecthers; i++) {
    //     init_pre_alloc_memory_pool(sb, &get_fetcher(cq, i)->pamp, 
    //                                sizeof(struct hk_cmt_info), 1024 * 1024 * 16,
    //                                alloc_cmt_info, free_cmt_info);
    // }
    
    // hk_start_memory_fetchers(cq);

    return cq;
}

void hk_free_cmt_queue(struct hk_cmt_queue *cq)
{   
    int i;
    if (cq) {
        // hk_stop_memory_fetchers(cq);
        // for (i = 0; i < cq->nfetchers; i++) {
        //     destroy_pre_alloc_memory_pool(&get_fetcher(cq, i)->pamp);
        // }
        // if (cq->fetchers) {
        //     kvfree(cq->fetchers);
        // }
        kfree(cq);
    }
}