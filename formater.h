#ifndef _FORMATER_H_
#define _FORMATER_H_

#define WOFS_HDR_MAGIC      0x4b4c5244 /* "KLRD" */
#define WOFS_HINT_EMPTY_BLK 0x0f0f0f0f
#define WOFS_HINT_OCCPY_BLK 0xffffffff

struct wofs_bhint_hdr {
    u32 magic;
    u32 hint;
    u32 hcrc32;
    u32 bcrc32;
} __attribute__((__packed__));

#endif /* _FORMATER_H_ */