#ifndef _HK_GENERIC_CACHEP_H_
#define _HK_GENERIC_CACHEP_H_

#include "hunter.h"

#define DEFINE_GENERIC_CACHEP(type) \
    struct kmem_cache *type##_cachep;

#define STRFY(x) #x
#define DECLARE_GENERIC_CACHEP(type, alloc_flags)                                             \
    extern struct kmem_cache *type##_cachep;                                                  \
    static inline int __init init_##type##_cache(void)                                               \
    {                                                                                         \
        type##_cachep = kmem_cache_create(STRFY(type##_cachep),                               \
                                          sizeof(struct type),                                \
                                          0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL); \
        if (type##_cachep == NULL)                                                            \
            return -ENOMEM;                                                                   \
        return 0;                                                                             \
    }                                                                                         \
    static inline void destroy_##type##_cache(void)                                                  \
    {                                                                                         \
        if (type##_cachep) {                                                                  \
            kmem_cache_destroy(type##_cachep);                                                \
            type##_cachep = NULL;                                                             \
        }                                                                                     \
    }                                                                                         \
    static inline struct type *hk_alloc_##type(void)                                                            \
    {                                                                                         \
        struct type *p;                                                                       \
        p = (struct type *)                                                                   \
            kmem_cache_zalloc(type##_cachep, alloc_flags);                                    \
        return p;                                                                             \
    }                                                                                         \
    static inline void hk_free_##type(struct type *node)                                                    \
    {                                                                                         \
        kmem_cache_free(type##_cachep, node);                                                 \
    }

DECLARE_GENERIC_CACHEP(obj_ref_inode, GFP_ATOMIC);
DECLARE_GENERIC_CACHEP(obj_ref_data, GFP_ATOMIC);
DECLARE_GENERIC_CACHEP(obj_ref_attr, GFP_ATOMIC);
DECLARE_GENERIC_CACHEP(obj_ref_dentry, GFP_ATOMIC);
DECLARE_GENERIC_CACHEP(claim_req, GFP_ATOMIC);

DECLARE_GENERIC_CACHEP(hk_range_node, GFP_ATOMIC);
DECLARE_GENERIC_CACHEP(hk_dentry_info, GFP_ATOMIC);
DECLARE_GENERIC_CACHEP(hk_cmt_info, GFP_ATOMIC);
DECLARE_GENERIC_CACHEP(hk_inode_info_header, GFP_ATOMIC);

DECLARE_GENERIC_CACHEP(tl_node, GFP_ATOMIC);

#endif