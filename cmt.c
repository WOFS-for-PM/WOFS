#include "hunter.h"

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

void hk_save_inode_state(struct inode *inode, struct hk_inode_state *state)
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

int hk_valid_hdr_background(struct super_block *sb, struct inode *inode, u64 blk_addr, u64 f_blk)
{
    struct hk_cmt_info *info;
    struct hk_sb_info *sbi = HK_SB(sb);

    info = hk_alloc_cmt_info(sb);
    info->type = CMT_VALID;
    info->ino = inode->i_ino;
    info->addr_start = blk_addr;
    info->addr_end = blk_addr + HK_PBLK_SZ(sbi);
    info->blk_start = f_blk;
    info->blk_end = f_blk;
    info->tstamp = get_version(sbi);

    hk_save_inode_state(inode, &info->state);

    hk_request_cmt(sb, info);

    return 0;
}

int hk_invalid_hdr_background(struct super_block *sb, struct inode *inode, u64 blk_addr, u64 f_blk)
{
    struct hk_cmt_info *info;
    struct hk_sb_info *sbi = HK_SB(sb);

    info = hk_alloc_cmt_info(sb);
    info->type = CMT_INVALID;
    info->ino = inode->i_ino;
    info->addr_start = blk_addr;
    info->addr_end = blk_addr + HK_PBLK_SZ(sbi);
    info->blk_start = f_blk;
    info->blk_end = f_blk;
    info->tstamp = get_version(sbi);

    hk_save_inode_state(inode, &info->state);

    hk_request_cmt(sb, info);

    return 0;
}

int hk_valid_range_background(struct super_block *sb, struct inode *inode, struct hk_cmt_batch *batch)
{
    struct hk_cmt_info *info;
    struct hk_sb_info *sbi = HK_SB(sb);

    info = hk_alloc_cmt_info(sb);
    info->type = CMT_VALID;
    info->ino = inode->i_ino;
    info->addr_start = batch->addr_start;
    info->addr_end = batch->addr_end;
    info->blk_start = batch->blk_start;
    info->blk_end = batch->blk_end;
    info->tstamp = get_version(sbi);

    hk_save_inode_state(inode, &info->state);

    hk_request_cmt(sb, info);

    return 0;
}

struct hk_cmt_info *hk_grab_cmt_info(struct super_block *sb, int key)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_cmt_queue *cq = sbi->cq;
    struct hk_cmt_info *info = NULL;
    struct ch_slot *slot;

    spin_lock(&cq->locks[key]);
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
    spin_unlock(&cq->locks[key]);
    return info;
}

int hk_process_single_cmt_info(struct super_block *sb, struct hk_cmt_info *info)
{
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_header *hdr, *hdr_traverse;
    struct hk_inode *pi;
    struct hk_inode_state *state = NULL;
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

    state = &info->state;
    hk_commit_inode_state(sb, state);

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
        init_waitqueue_head(&sbi->cmt_waits[i]);

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

struct hk_cmt_queue *hk_init_cmt_queue(void)
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

    return cq;
}

void hk_free_cmt_queue(struct hk_cmt_queue *cq)
{
    if (cq) {
        kfree(cq);
    }
}