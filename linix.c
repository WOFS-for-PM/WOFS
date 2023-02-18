/*
 * HUNTER Recovery routines.
 *
 * Copyright 2022-2023 Regents of the University of Harbin Institute of Technology, Shenzhen
 * Computer science and technology, Yanqi Pan <deadpoolmine@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "hunter.h"

int linix_init(struct linix *ix, u64 num_slots) 
{
    ix->num_slots = num_slots;
    if (num_slots == 0) {
        ix->slots = NULL;
    }
    else {
        ix->slots = kvcalloc(ix->num_slots, sizeof(struct linslot), GFP_KERNEL);
    }
    return 0;
}

int linix_destroy(struct linix *ix) 
{
    if (ix->slots) {
        kvfree(ix->slots);
    }
    return 0;
}

void * __must_check kvrealloc(void* old_ptr, size_t old_size, size_t new_size, gfp_t mode) 
{
    void *buf;

    buf = kvmalloc(new_size, mode);
    if (buf) {
        memcpy(buf, old_ptr, ((old_size < new_size) ? old_size : new_size));
        kvfree(old_ptr);
    }
    
    return buf;
}

/* This should be changed to kvmalloc */
int linix_extend(struct linix *ix) 
{
    struct linslot *new_slots;
    new_slots = kvrealloc(ix->slots, ix->num_slots * IX_SLOT_SZ, 2 * ix->num_slots * IX_SLOT_SZ, GFP_KERNEL);

    if (new_slots == NULL)
    {
        return -1;
    }
    memset(new_slots + ix->num_slots, 0,
           ix->num_slots * IX_SLOT_SZ);

    ix->num_slots = 2 * ix->num_slots;
    ix->slots = new_slots;

    return 0;
}

int linix_shrink(struct linix *ix)
{
    struct linslot *new_slots;
    new_slots = kvrealloc(ix->slots, ix->num_slots * IX_SLOT_SZ, 
                          ix->num_slots / 2 * IX_SLOT_SZ, GFP_KERNEL);

    if (new_slots == NULL)
    {
        return -1;
    }

    ix->num_slots = ix->num_slots / 2;
    ix->slots = new_slots;

    return 0;
}

/* TODO: Customizing measuring time  */
/* return the value of index */
u64 linix_get(struct linix *ix, u64 index)
{
    u64 blk_addr;
    INIT_TIMING(index_time);
    HK_START_TIMING(linix_get_t, index_time);
    if (index >= ix->num_slots)
    {
        HK_END_TIMING(linix_get_t, index_time);
        return 0;
    }
    blk_addr = ix->slots[index].blk_addr;
    HK_END_TIMING(linix_get_t, index_time);
    return blk_addr;
}

/* Inode Lock must be held before linix insert, and blk_addr */
int linix_insert(struct linix *ix, u64 index, u64 blk_addr, bool extend) 
{
    INIT_TIMING(index_time);
    HK_START_TIMING(linix_set_t, index_time);
    if (extend) {
        while (index >= ix->num_slots) {
            linix_extend(ix);
        }
    }

    if (index >= ix->num_slots) {
        HK_END_TIMING(linix_set_t, index_time);
        return -1;
    }

    ix->slots[index].blk_addr = blk_addr;
    HK_END_TIMING(linix_set_t, index_time);
    return 0;
}

/* last_index is the last valid index determined by user */
int linix_delete(struct linix *ix, u64 index, u64 last_index, bool shrink) 
{
    struct hk_inode_info_header *sih = container_of(ix, struct hk_inode_info_header, ix);
    ix->slots[index].blk_addr = 0;
    
    if (shrink && ix->num_slots > HK_LINIX_SLOTS) {
        if (last_index + 1 <= ix->num_slots / 2) {
            linix_shrink(ix);
        }
    }

    return 0;
}