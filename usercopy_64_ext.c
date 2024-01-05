#include <linux/export.h>
#include <linux/highmem.h>
#include <linux/uaccess.h>

unsigned long copy_user_handle_tail(char *to, char *from, unsigned len)
{
    for (; len; --len, to++) {
        char c;

        if (__get_user_nocheck(c, from++, sizeof(char)))
            break;
        if (__put_user_nocheck(c, to, sizeof(char)))
            break;
    }
    clac();
    return len;
}