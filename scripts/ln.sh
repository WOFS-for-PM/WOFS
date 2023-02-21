#!/usr/bin/bash
echo 123 > /mnt/c
ln -s /mnt/c /mnt/c_soft
stat /mnt/c_soft
ls /mnt/
cat /mnt/c_soft

# hard link
ln /mnt/c /mnt/c_hard
cat /mnt/c_hard

mkdir -p tmp
filebench -f fileserver-50.f