#!/usr/bin/bash

if [ ! "$1" ]; then
    timing=0
else
    timing=$1
fi

make -j32

sudo umount /mnt/pmem0

sudo rmmod hunter 
sudo insmod hunter.ko measure_timing="$timing"


sudo mount -t HUNTER -o init,meta_local,meta_async /dev/pmem0 /mnt/pmem0