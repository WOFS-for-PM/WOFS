#!/usr/bin/env bash

bash setup.sh 
sudo fio -filename=/mnt/pmem0/file -fallocate=none -direct=0 -iodepth 1 -rw=write -ioengine=sync -bs=4k -size=1024M -name=test 
cat /proc/fs/HUNTER/pmem0/timing_stats > LOG 
umount /mnt/pmem0