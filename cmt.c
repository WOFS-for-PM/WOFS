#include "hunter.h"

wait_queue_head_t  cmt_finish_wq;
int                cmt_finished[HK_CMT_WORKER_NUM];

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

int hk_request_cmt(struct super_block *sb, struct hk_cmt_info *info)
{
    struct hk_sb_info   *sbi = HK_SB(sb);
    struct hk_cmt_queue *cq = sbi->cq;
    u64 ino;
    int key;
    
    ino = info->ino;

    key = hash_min(ino, HK_CMT_QUEUE_BITS);
    
    mutex_lock(&cq->locks[key]);
    chash_add_head(cq->table, &info->slot, key);
    mutex_unlock(&cq->locks[key]);
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
    info->addr_end = blk_addr + HK_PBLK_SZ;
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
    info->addr_end = blk_addr + HK_PBLK_SZ;
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
    struct hk_sb_info   *sbi = HK_SB(sb);
    struct hk_cmt_queue *cq = sbi->cq;
    struct hk_cmt_info  *info = NULL;
    struct ch_slot      *slot;
    
    mutex_lock(&cq->locks[key]);
    slot = chash_last(cq->table, key);
    if (chash_is_sentinal(cq->table, key, slot)) {
        goto out;
    }
    info = chlist_entry(slot, struct hk_cmt_info, slot);
    chash_del(&info->slot);
out:
    mutex_unlock(&cq->locks[key]);
    return info;
}

int hk_process_single_cmt_info(struct super_block *sb, struct hk_cmt_info *info)
{
    struct hk_sb_info     *sbi = HK_SB(sb);
    struct hk_header      *hdr, *hdr_traverse;
    struct hk_inode       *pi;
    struct inode          *inode = NULL;
    struct hk_inode_state *state = NULL;
    struct hk_layout_info *layout = NULL, *layout_migrated = NULL;
    u64                   addr, blk, index, addr_migrated;
    u64                   ino = info->ino;
    u64                   addr_start = info->addr_start;
    u64                   addr_end = info->addr_end;
    u64                   blk_start = info->blk_start;
    u64                   blk_end = info->blk_end;

    hdr = sm_get_hdr_by_addr(sb, addr_start);
    layout = sm_get_layout_by_hdr(sb, hdr);
    
    /* lock layout then lock nvm inode, preventing deadlock from equlizer */
    use_layout(layout);
    use_nvm_inode(sb, ino);
    pi = hk_get_inode_by_ino(sb, ino);
    for (addr = addr_start, blk = blk_start; addr < addr_end; addr += HK_PBLK_SZ, blk += 1)
    {
        hdr = sm_get_hdr_by_addr(sb, addr);
        switch (info->type)
        {
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
                traverse_inode_hdr(sbi, pi, hdr_traverse) {
                    /* We must ensure that no any invalidator is running at this time */
                    if (blk == hdr_traverse->f_blk && hdr_traverse->valid) {
                        addr_migrated = sm_get_addr_by_hdr(sb, hdr_traverse);
                        layout = sm_get_layout_by_hdr(sb, hdr);
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
            }
            else if (hdr->tstamp <= info->tstamp) {
                sm_invalid_hdr(sb, addr, ino);           
            }
            else {
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
    unuse_layout(layout);

    hk_free_cmt_info(info);

    return 0;
}

struct hk_cmt_worker_param
{
    struct super_block    *sb;
    int                   work_id;
};

/* TODO: Signal Bugs that Occurs in GC */
/* Reproduce scripts in QEMU:
    qemu-system-x86_64 \
        -kernel ~/linux-nova/arch/x86_64/boot/bzImage \
        -nographic \
        -smp 32 \
        -initrd /home/deadpool/Playground/rootfs/initramfs.cpio \
        -append "root=/dev/ram rdinit=/sbin/init console=ttyS0 nokaslr memmap=1G!1G" \
        -s -S \
        -m 8G
*/
static int hk_cmt_worker_thread(void *arg)
{
    struct hk_cmt_worker_param *param = (struct hk_cmt_worker_param *)arg;
    struct super_block *sb = param->sb;
    struct hk_sb_info  *sbi = HK_SB(sb);
    struct hk_cmt_info *info;
    int work_id = param->work_id;
    int key, start_key, end_key; 

    start_key = work_id * (1 << HK_CMT_QUEUE_BITS) / HK_CMT_WORKER_NUM;
    end_key = (work_id + 1) * (1 << HK_CMT_QUEUE_BITS) / HK_CMT_WORKER_NUM;

    allow_signal(SIGINT);

    while (!kthread_should_stop()) {
        ssleep_interruptible(HK_CMT_TIME_GAP);

        for (key = start_key; key < end_key; key++) {
            up_invalidator(sb);
            while ((info = hk_grab_cmt_info(sb, key)) != NULL) {
                hk_process_single_cmt_info(sb, info);
            }
            cond_resched();
            down_invalidator(sb);
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

void hk_start_cmt_workers(struct super_block *sb)
{
    struct hk_cmt_worker_param *param;
    struct hk_sb_info  *sbi = HK_SB(sb);
    int ret;
    int i;
    
    init_waitqueue_head(&cmt_finish_wq);

    for (i = 0; i < HK_CMT_WORKER_NUM; i++) {
        param = kmalloc(sizeof(struct hk_cmt_worker_param), GFP_KERNEL);
        param->sb = sb;
        param->work_id = i;
        
        cmt_finished[i] = 0;
        sbi->cmt_workers[i] = kthread_create(hk_cmt_worker_thread, 
                                             param, "hk_cmt_worker_%d", i);
        
        wake_up_process(sbi->cmt_workers[i]);
        hk_info("start cmt workers %d\n", i);
    }
}

void hk_stop_cmt_workers(struct super_block *sb)
{
    struct hk_sb_info  *sbi = HK_SB(sb);
    int i;

    for (i = 0; i < HK_CMT_WORKER_NUM; i++) {
        send_sig(SIGINT, sbi->cmt_workers[i], 1);
        kthread_stop(sbi->cmt_workers[i]);
        sbi->cmt_workers[i] = NULL;
    }
    
    wait_to_finish_cmt();

    hk_info("stop %d cmt workers\n", HK_CMT_WORKER_NUM);
}

void hk_flush_cmt_inode_fast(struct super_block *sb, u64 ino)
{
    struct hk_sb_info   *sbi = HK_SB(sb);
    struct hk_cmt_queue *cq = sbi->cq;
    struct hk_cmt_info  *info;
    struct ch_slot      *slot;
    struct ch_slot      *slot_prev;
    int key;

    key = hash_min(ino, HK_CMT_QUEUE_BITS);

    mutex_lock(&cq->locks[key]);
    
    slot = chash_last(cq->table, key);
    
    /* Prevent Equlizer's function */
    up_invalidator(sb);
    while (!chash_is_sentinal(cq->table, key, slot)) {
        info = chlist_entry(slot, struct hk_cmt_info, slot);
        slot_prev = slot->prev;
        if (info->ino == ino) {
            chash_del(&info->slot);
            hk_process_single_cmt_info(sb, info);
        }
        slot = slot_prev;
        cond_resched();
    }
    down_invalidator(sb);
    
    mutex_unlock(&cq->locks[key]);
}

void hk_flush_cmt_queue(struct super_block *sb)
{
    struct hk_cmt_info *info;
    int key;

    for (key = 0; key < (1 << HK_CMT_QUEUE_BITS); key++) {
        while((info = hk_grab_cmt_info(sb, key)) != NULL) {
            hk_process_single_cmt_info(sb, info);
            cond_resched();
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
        mutex_init(&cq->locks[i]);
    }

    return cq;
}

void hk_free_cmt_queue(struct hk_cmt_queue *cq)
{
    if (cq) {
        kfree(cq);
    }
}