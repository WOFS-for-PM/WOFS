#include "common.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TEST_RAW            0
#define TEST_RW             1
#define TEST_PARTIAL_APPEND 2

#define REGISTER_TEST(NAME) \
    int test_##NAME(int fd, int argc, char const *argv[])

REGISTER_TEST(RAW)
{
    char *wbuf = (char *)malloc(DEFAULT_IO_SIZE);
    char *rbuf = (char *)malloc(DEFAULT_IO_SIZE);
    write(fd, wbuf, DEFAULT_IO_SIZE);
    read(fd, rbuf, DEFAULT_IO_SIZE);
    if (memcmp(wbuf, rbuf, DEFAULT_IO_SIZE) != 0) {
        return -1;
    }
    free(wbuf);
    free(rbuf);
    return 0;
}

REGISTER_TEST(RW)
{
    char *wbuf = (char *)malloc(DEFAULT_IO_SIZE);
    char *rbuf = (char *)malloc(DEFAULT_IO_SIZE + PAGE_SIZE / 2);
    char *wwin;
    int wi_blk, wi_byte;
    int ww_blk, ww_byte;
    int ri_blk, ri_byte;
    int ret = 0;

    // Step 1: |1|2|3|4|
    // Step 2:  |5|
    // Step 3:   |6|7|
    // Step 4: |8|9|0|
    // Step 5:  |1|2|3|
    // Step 5:        |4|

    /* Step 1 */
    for (wi_blk = 0; wi_blk < DEFAULT_IO_SIZE / PAGE_SIZE; wi_blk++) {
        for (wi_byte = wi_blk * PAGE_SIZE; wi_byte < (wi_blk + 1) * PAGE_SIZE; wi_byte++) {
            wbuf[wi_byte] = wi_blk + 1;
        }
    }
    write(fd, wbuf, DEFAULT_IO_SIZE);

    /* Step 2 */
    wwin = (char *)malloc(PAGE_SIZE);
    for (ww_byte = 0; ww_byte < PAGE_SIZE; ww_byte++) {
        wwin[ww_byte] = 5;
    }
    lseek(fd, PAGE_SIZE / 2, SEEK_SET);
    write(fd, wwin, PAGE_SIZE);
    free(wwin);

    /* Step 3 */
    wwin = (char *)malloc(PAGE_SIZE * 2);
    for (ww_blk = 0; ww_blk < 2; ww_blk++) {
        for (ww_byte = ww_blk * PAGE_SIZE; ww_byte < (ww_blk + 1) * PAGE_SIZE; ww_byte++) {
            wwin[ww_byte] = ww_blk + 6;
        }
    }
    lseek(fd, PAGE_SIZE, SEEK_SET);
    write(fd, wwin, PAGE_SIZE * 2);
    free(wwin);

    /* Step 4 */
    wwin = (char *)malloc(PAGE_SIZE * 3);
    for (ww_blk = 0; ww_blk < 3; ww_blk++) {
        for (ww_byte = ww_blk * PAGE_SIZE; ww_byte < (ww_blk + 1) * PAGE_SIZE; ww_byte++) {
            wwin[ww_byte] = (ww_blk + 8) % 9;
        }
    }
    lseek(fd, 0, SEEK_SET);
    write(fd, wwin, PAGE_SIZE * 3);
    free(wwin);

    /* Step 5 */
    wwin = (char *)malloc(PAGE_SIZE * 3);
    for (ww_blk = 0; ww_blk < 3; ww_blk++) {
        for (ww_byte = ww_blk * PAGE_SIZE; ww_byte < (ww_blk + 1) * PAGE_SIZE; ww_byte++) {
            wwin[ww_byte] = ww_blk + 1;
        }
    }
    lseek(fd, PAGE_SIZE / 2, SEEK_SET);
    write(fd, wwin, PAGE_SIZE * 3);
    free(wwin);

    /* Last */
    wwin = (char *)malloc(PAGE_SIZE);
    for (ww_byte = 0; ww_byte < PAGE_SIZE; ww_byte++) {
        wwin[ww_byte] = 4;
    }
    lseek(fd, PAGE_SIZE * 3 + PAGE_SIZE / 2, SEEK_SET);
    write(fd, wwin, PAGE_SIZE);
    free(wwin);

    /* Check if correct */
    lseek(fd, 0, SEEK_SET);
    read(fd, rbuf, DEFAULT_IO_SIZE + PAGE_SIZE / 2);

    for (ri_byte = 0; ri_byte < PAGE_SIZE / 2; ri_byte++) {
        if (rbuf[ri_byte] != 8) {
            ret = -1;
            goto out_err;
        }
    }

    for (ri_byte = PAGE_SIZE / 2; ri_byte < PAGE_SIZE + PAGE_SIZE / 2; ri_byte++) {
        if (rbuf[ri_byte] != 1) {
            ret = -2;
            goto out_err;
        }
    }

    for (ri_byte = PAGE_SIZE + PAGE_SIZE / 2; ri_byte < PAGE_SIZE * 2 + PAGE_SIZE / 2; ri_byte++) {
        if (rbuf[ri_byte] != 2) {
            ret = -3;
            goto out_err;
        }
    }

    for (ri_byte = PAGE_SIZE * 2 + PAGE_SIZE / 2; ri_byte < PAGE_SIZE * 3 + PAGE_SIZE / 2; ri_byte++) {
        if (rbuf[ri_byte] != 3) {
            ret = -4;
            goto out_err;
        }
    }

    for (ri_byte = PAGE_SIZE * 3 + PAGE_SIZE / 2; ri_byte < PAGE_SIZE * 4 + PAGE_SIZE / 2; ri_byte++) {
        if (rbuf[ri_byte] != 4) {
            ret = -5;
            goto out_err;
        }
    }

    free(wbuf);
    free(rbuf);
    return ret;

out_err:
    for (ri_byte = 0; ri_byte < PAGE_SIZE / 2; ri_byte++) {
        printf("%d", rbuf[ri_byte]);
        if (ri_byte % 80 == 0 && ri_byte != 0) {
            printf("\n");
        }
    }

    printf("\n");

    for (ri_byte = PAGE_SIZE / 2; ri_byte < PAGE_SIZE + PAGE_SIZE / 2; ri_byte++) {
        printf("%d", rbuf[ri_byte]);
        if ((ri_byte - PAGE_SIZE / 2) % 80 == 0 && (ri_byte - PAGE_SIZE / 2) != 0) {
            printf("\n");
        }
    }

    printf("\n");

    for (ri_byte = PAGE_SIZE + PAGE_SIZE / 2; ri_byte < PAGE_SIZE * 2 + PAGE_SIZE / 2; ri_byte++) {
        printf("%d", rbuf[ri_byte]);
        if ((ri_byte - (PAGE_SIZE + PAGE_SIZE / 2)) % 80 == 0 && (ri_byte - (PAGE_SIZE + PAGE_SIZE / 2)) != 0) {
            printf("\n");
        }
    }

    printf("\n");

    for (ri_byte = PAGE_SIZE * 2 + PAGE_SIZE / 2; ri_byte < PAGE_SIZE * 3 + PAGE_SIZE / 2; ri_byte++) {
        printf("%d", rbuf[ri_byte]);
        if ((ri_byte - (PAGE_SIZE * 2 + PAGE_SIZE / 2)) % 80 == 0 && (ri_byte - (PAGE_SIZE * 2 + PAGE_SIZE / 2)) != 0) {
            printf("\n");
        }
    }

    printf("\n");

    for (ri_byte = PAGE_SIZE * 3 + PAGE_SIZE / 2; ri_byte < PAGE_SIZE * 4 + PAGE_SIZE / 2; ri_byte++) {
        printf("%d", rbuf[ri_byte]);
        if ((ri_byte - (PAGE_SIZE * 3 + PAGE_SIZE / 2)) % 80 == 0 && (ri_byte - (PAGE_SIZE * 3 + PAGE_SIZE / 2)) != 0) {
            printf("\n");
        }
    }

    printf("\n");

    free(wbuf);
    free(rbuf);
    return ret;
}

REGISTER_TEST(PARTIAL_APPEND)
{
    const int append_size = 35;
    char *wbuf = (char *)malloc(DEFAULT_IO_SIZE);
    char *rbuf = (char *)malloc(DEFAULT_IO_SIZE);
    int append_times = DEFAULT_IO_SIZE / append_size;
    int remain_size = DEFAULT_IO_SIZE % append_size;
    int ret = 0;

    for (int i = 0; i < DEFAULT_IO_SIZE; i++) {
        wbuf[i] = i % 256;
    }

    for (int i = 0; i < append_times; i++) {
        write(fd, wbuf + i * append_size, append_size);
    }

    if (remain_size != 0) {
        write(fd, wbuf + append_times * append_size, remain_size);
    }

    lseek(fd, 0, SEEK_SET);
    read(fd, rbuf, DEFAULT_IO_SIZE);

    if (memcmp(wbuf, rbuf, DEFAULT_IO_SIZE) != 0) {
        ret = -1;
        goto out;
    }

out:
    free(wbuf);
    free(rbuf);
    return ret;
}

extern char *optarg;

void usage()
{
    printf("WOFS Kernel Testsuite by Deadpool\n");
    printf("Description: This file will perform corner case I/O tests\n");
    printf("-f file     <filename>\n");
    printf("-o options  <num>\n");
    printf("            - 0 for read after write\n");
    printf("            - 1 for random write\n");
    printf("            - 2 for partial small append\n");
    printf("Example: ./rw_test -f /mnt/pmem0 -o 1\n");
}

int main(int argc, char const *argv[])
{
    char *optstring = "f:o:h";
    int fd, op, opt;
    int filelen = 0;
    char filepath[128] = {0};
    int ret;

    while ((opt = getopt(argc, argv, optstring)) != -1) {
        switch (opt) {
        case 'f':
            filelen = strlen(optarg);
            if (filelen > 1 && optarg[filelen - 1] == '/') {
                filelen -= 1;
            }
            strcpy(filepath, optarg);
            break;
        case 'o':
            op = atoi(optarg);
            break;
        case 'h':
            usage();
            exit(1);
        default:
            printf("Bad usage!\n");
            usage();
            exit(1);
        }
    }

    fd = open(filepath, O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        printf("open %s failed: %s\n", filepath, strerror(errno));
        return -1;
    }

    switch (op) {
    case TEST_RAW:
        ret = test_RAW(fd, argc, argv);
        if (ret) {
            printf("Read/write failed\n");
        } else {
            printf("Read/Write ok!\n");
        }
        break;
    case TEST_RW:
        ret = test_RW(fd, argc, argv);
        if (ret) {
            printf("Random Read/write failed, %d\n", ret);
        } else {
            printf("Random Read/Write ok!\n");
        }
        break;
    case TEST_PARTIAL_APPEND:
        ret = test_PARTIAL_APPEND(fd, argc, argv);
        if (ret) {
            printf("Partial append failed\n");
        } else {
            printf("Partial append ok!\n");
        }
        break;
    default:
        break;
    }

    close(fd);
    return 0;
}
