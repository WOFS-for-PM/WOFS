#!/usr/bin/env bash

# shellcheck source=measure_pm_io.sh
source measure_pm_io.sh


bash /home/deadpool/HUNTER-REPO/hunter-kernel/setup.sh

pmem_id=$(get_pmem_id_by_name pmem0)
echo "pmem_id: $pmem_id"


measure_start "$pmem_id"
sync; echo 3 > /proc/sys/vm/drop_caches
sudo fio -filename=/mnt/pmem0/file -fallocate=none -direct=0 -iodepth 1 -rw=write -ioengine=sync -bs=4k -size=1024M -name=test
measure_end "$pmem_id"

cat /proc/fs/HUNTER/pmem0/timing_stats > ../LOG