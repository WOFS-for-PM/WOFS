#ifndef _WOFS_DW_H_
#define _WOFS_DW_H_

#include "wofs.h"

/* dynamic workload */
struct wofs_dym_wkld
{
    spinlock_t dw_lock;
    int hstart;
    int hend;
    size_t histories[WOFS_HISTORY_WINDOWS];
};

static inline void wofs_dw_init(struct wofs_dym_wkld *dw, size_t startup)
{
    int i;
    dw->hstart = 0;
    dw->hend = WOFS_HISTORY_WINDOWS - 1;
    spin_lock_init(&dw->dw_lock);
    for (i = 0; i < WOFS_HISTORY_WINDOWS; i++) {
        dw->histories[i] = startup;
    }
}

static inline void wofs_dw_forward(struct wofs_dym_wkld *dw, size_t value) 
{
    spin_lock(&dw->dw_lock);
    dw->histories[dw->hstart] = value;
    dw->hstart = (dw->hstart + 1) % WOFS_HISTORY_WINDOWS;
    dw->hend = (dw->hend + 1) % WOFS_HISTORY_WINDOWS;
    spin_unlock(&dw->dw_lock);
}

static inline size_t wofs_dw_stat_avg(struct wofs_dym_wkld *dw)
{
    int    i;
    size_t total = 0;
    size_t avg = 0;

    spin_lock(&dw->dw_lock);
    for (i = 0; i < WOFS_HISTORY_WINDOWS; i++) {
        total += dw->histories[i];
    }
    avg = total / WOFS_HISTORY_WINDOWS;
    spin_unlock(&dw->dw_lock);

    return avg;
}

#endif