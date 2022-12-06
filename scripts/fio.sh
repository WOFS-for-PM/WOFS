#!/usr/bin/env bash
bash /home/deadpool/HUNTER-REPO/hunter-kernel/setup.sh /home/deadpool/HUNTER-REPO/tests/tools/configs/hunter/sync/config.mt.nowprotect.json

sudo fio -filename=/mnt/pmem0/file -fallocate=none -direct=0 -iodepth 1 -rw=write -ioengine=sync -bs=4k -size=1024M -name=test

cat /proc/fs/HUNTER/pmem0/timing_stats > LOG