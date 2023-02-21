#ifndef _RNG_LOCK_H
#define _RNG_LOCK_H

#include "hunter.h"

typedef struct rng_lock{
    spinlock_t *locks;
    int num_locks;
    int (*distribute) (struct rng_lock *lock, u64 key);    
} rng_lock_t;

static inline int default_distribute(rng_lock_t *lock, u64 key)
{
    return key % lock->num_locks;
}

static inline int rng_lock_init(rng_lock_t *lock, int num_locks, int (*distribute) (rng_lock_t *lock, u64 key))
{
    int i;
    lock->locks = (spinlock_t *)kmalloc(sizeof(spinlock_t) * num_locks, GFP_KERNEL);
    if(!lock->locks)
        return -1;
    for(i = 0; i < num_locks; i++)
        spin_lock_init(&lock->locks[i]);
    lock->num_locks = num_locks;
    if(distribute)
        lock->distribute = distribute;
    else
        lock->distribute = default_distribute;
    return 0;
}

static inline void rng_lock_destroy(rng_lock_t *lock)
{
    if (lock->locks)
        kfree(lock->locks);
}

static inline void rng_lock(rng_lock_t *lock, u64 key)
{
    spin_lock(&lock->locks[lock->distribute(lock, key)]);
}

static inline void rng_unlock(rng_lock_t *lock, u64 key)
{
    spin_unlock(&lock->locks[lock->distribute(lock, key)]);
}

#endif