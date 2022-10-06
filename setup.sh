#!/usr/bin/bash

if [ ! "$1" ]; then
    timing=0
else
    timing=$1
fi

make -j32
sudo rmmod hunter 
sudo insmod hunter.ko measure_timing="$timing"


sudo mount -t HUNTER -o init /dev/pmem0 /mnt/pmem0