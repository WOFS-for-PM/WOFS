/**
 * Copyright (C) 2023 Deadpool
 * 
 * This file is for range node management
 * 
 * hunter-kernel is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * 
 * hunter-kernel is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with hunter-kernel.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "hunter.h"

void hk_range_trv(struct list_head *head)
{
    struct hk_range_node *cur;
    struct list_head *pos;

    list_for_each(pos, head)
    {
        cur = list_entry(pos, struct hk_range_node, node);
        hk_info("%s: %lu %lu\n", __func__, cur->low, cur->high);
    }
}

int hk_range_insert_range(struct super_block *sb, struct list_head *head,
                          unsigned long range_low, unsigned long range_high)
{
    struct hk_range_node *cur;
    struct hk_range_node *new;
    struct list_head *pos;
    unsigned long _range_low;
    unsigned long _range_high;
    bool is_insert = false;

    list_for_each(pos, head)
    {
        cur = list_entry(pos, struct hk_range_node, node);
        _range_low = cur->low;
        _range_high = cur->high;
        if (range_high == _range_low - 1) {
            cur->low = range_low;
            is_insert = true;
            break;
        } else if (range_low == _range_high + 1) {
            cur->high = range_high;
            is_insert = true;
            break;
        } else if ((_range_low <= range_low && range_low <= _range_high) ||
                   (_range_low <= range_high && range_high <= _range_high)) {
            return -1;
        }
    }

    if (!is_insert) {
        new = hk_alloc_hk_range_node();
        new->low = range_low;
        new->high = range_high;

        list_add_tail(&new->node, head);
    }

    return 0;
}

int hk_range_insert_value(struct super_block *sb, struct list_head *head, unsigned long value)
{
    struct hk_range_node *cur;
    struct hk_range_node *new;
    struct list_head *pos;
    unsigned long range_low;
    unsigned long range_high;
    bool is_insert = false;
    int retries = 0;

    list_for_each(pos, head)
    {
        cur = list_entry(pos, struct hk_range_node, node);
        range_low = cur->low;
        range_high = cur->high;
        if (value == range_low - 1) {
            cur->low = value;
            is_insert = true;
            break;
        } else if (value == range_high + 1) {
            cur->high = value;
            is_insert = true;
            break;
        } else if (value >= range_low && value <= range_high) {
            return -1;
        }
        retries++;
        /* We prevent too many times retries. */
        if (retries > HK_MLIST_INST_MAXRETRIES) {
            break;
        }
    }

    if (!is_insert) {
        new = hk_alloc_hk_range_node();
        new->low = value;
        new->high = value;

        list_add_tail(&new->node, head);
    }
    return 0;
}

bool hk_range_find_value(struct super_block *sb, struct list_head *head, unsigned long value)
{
    struct hk_range_node *cur;
    struct hk_range_node *new;
    struct list_head *pos;
    unsigned long range_low;
    unsigned long range_high;
    bool is_find = false;

    list_for_each(pos, head)
    {
        cur = list_entry(pos, struct hk_range_node, node);
        range_low = cur->low;
        range_high = cur->high;
        if (value >= range_low && value <= range_high) {
            is_find = true;
            break;
        }
    }

    return is_find;
}

int hk_range_remove(struct super_block *sb, struct list_head *head, unsigned long value)
{
    struct hk_range_node *new;
    struct hk_range_node *cur;
    struct list_head *pos, *q;
    unsigned long range_low;
    unsigned long range_high;

    list_for_each_safe(pos, q, head)
    {
        cur = list_entry(pos, struct hk_range_node, node);
        BUG_ON(cur == NULL);
        range_low = cur->low;
        range_high = cur->high;
        if (range_low <= value && value <= range_high) {
            if (range_low == range_high) {
                list_del(pos);
                hk_free_hk_range_node(cur);
                return 0;
            } else if (range_low == value) {
                cur->low = value + 1;
                return 0;
            } else if (range_high == value) {
                cur->high = value - 1;
                return 0;
            } else {
                new = hk_alloc_hk_range_node();
                BUG_ON(new == NULL);
                cur->high = value - 1;
                new->low = value + 1;
                new->high = range_high;
                list_add_tail(&new->node, pos);
                return 0;
            }
        }
    }

    return -1;
}

/* TODO: Add indictaor */
int hk_range_remove_range(struct super_block *sb, struct list_head *head,
                          unsigned long range_low, unsigned long range_high)
{
    struct hk_range_node *cur;
    struct hk_range_node *new;
    struct list_head *pos, *q;
    unsigned long _range_low;
    unsigned long _range_high;

    list_for_each_safe(pos, q, head)
    {
        cur = list_entry(pos, struct hk_range_node, node);
        _range_low = cur->low;
        _range_high = cur->high;

        if ((_range_low <= range_low && range_low <= _range_high) ||
            (_range_low <= range_high && range_high <= _range_high)) {

            if (range_low <= _range_low && _range_high <= range_high) {
                list_del(pos);
                hk_free_hk_range_node(cur);
            } else if (range_low <= _range_low && _range_high > range_high) {
                cur->low = range_high + 1;
            } else if (range_low > _range_low && _range_high <= range_high) {
                cur->high = range_low - 1;
            } else if (range_low > _range_low && _range_high > range_high) {
                cur->high = range_low - 1;
                new = hk_alloc_hk_range_node();
                new->low = range_high + 1;
                new->high = _range_high;
                list_add_tail(&new->node, pos);
            }
        }
    }

    return 0;
}

unsigned long hk_range_pop(struct list_head *head, u64 *len)
{
    struct hk_range_node *cur;
    struct list_head *pos, *q;
    unsigned long range_low;
    unsigned long range_high;
    unsigned long value;

    list_for_each_safe(pos, q, head)
    {
        cur = list_entry(pos, struct hk_range_node, node);
        range_low = cur->low;
        range_high = cur->high;
        if (range_low + *len - 1 >= range_high) {
            value = range_low;
            *len = range_high - range_low + 1;
            list_del(pos);
            hk_free_hk_range_node(cur);
            return value;
        } else {
            value = range_low;
            cur->low += *len;
            return value;
        }
    }

    return -1;
}

void hk_range_free_all(struct list_head *head)
{
    struct hk_range_node *cur;
    struct list_head *pos, *q;

    list_for_each_safe(pos, q, head)
    {
        cur = list_entry(pos, struct hk_range_node, node);
        list_del(pos);
        hk_free_hk_range_node(cur);
    }
}