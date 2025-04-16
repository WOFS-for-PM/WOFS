#!/usr/bin/bash

# for debugging snippts
# Init
mkdir mnt && mount -t WOFS -o init /dev/pmem0 /mnt && cd /mnt
# Create
echo 123 >c
# umount
cd .. && umount mnt
# Remount
mount -t WOFS /dev/pmem0 /mnt && cd /mnt && ls
# Remove
rm c
# umount
cd .. && umount mnt
# Remount
mount -t WOFS /dev/pmem0 /mnt && cd /mnt && ls
