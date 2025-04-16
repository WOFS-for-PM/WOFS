mkdir mnt && mount -t WOFS -o init /dev/pmem0 /mnt
cat /proc/fs/WOFS/pmem0/timing_stats