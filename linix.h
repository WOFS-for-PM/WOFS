#ifndef _WOFS_LINIX_H
#define _WOFS_LINIX_H

#include "wofs.h"

struct linslot;

#define IX_SLOT_SZ sizeof(struct linslot)

struct linslot {
    u64 blk_addr;
};

struct linix {
    u64 num_slots;
    struct linslot *slots;
};

#endif /* _WOFS_LINIX_H */
