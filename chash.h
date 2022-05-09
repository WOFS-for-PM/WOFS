#ifndef _HK_CHASH_H_
#define _HK_CHASH_H_

/* circular hash table implement */
struct ch_slot
{
    struct ch_slot *next;
    struct ch_slot *prev;
};


#define DEFINE_CHASHTABLE(table, bits) \
    struct ch_slot table[1 << (bits)]

static void chash_init(struct ch_slot *table, int bits)
{
    int i;
    struct ch_slot *sentinal;
    for (i = 0; i < (1 << bits); i++)
    {
        sentinal = &table[i];
        sentinal->next = sentinal;
        sentinal->prev = sentinal;
    }
} 

static void chash_add_head(struct ch_slot *table, struct ch_slot *slot, int key)
{
    struct ch_slot *sentinal = &table[key];
    slot->next = sentinal->next;
    slot->prev = sentinal;
    sentinal->next->prev = slot;
    sentinal->next = slot;
}

static void chash_del(struct ch_slot *slot)
{
    slot->prev->next = slot->next;
    slot->next->prev = slot->prev;
}

static struct ch_slot *chash_last(struct ch_slot *table, int key)
{
    struct ch_slot *sentinal = &table[key];
    return sentinal->prev;
}


#define chash_is_sentinal(table, key, slot) \
    ((slot) == &(table)[key])

#define chash_for_each_possible(table, slot, key) \
    for (slot = (table)[key].next; slot != &(table)[key]; slot = slot->next)

#define chlist_entry(ptr, type, member) container_of(ptr, type, member)
#endif