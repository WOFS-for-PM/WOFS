#!/usr/bin/bash



#SECTION: Color Preset
CLR_BLACK="\033[30m"
CLR_RED="\033[31m"
CLR_GREEN="\033[32m"
CLR_YELLOW="\033[33m"
CLR_BLUD="\033[34m"
CLR_PURPLE="\033[35m"
CLR_BLUE="\033[36m"
CLR_GREY="\033[37m"

CLR_END="\033[0m"
#!SECTION


ORIGINAL=$PWD
WORK_DIR=$(dirname "$0")
MNT_POINT=/mnt/pmem0

# build project
cd "$WORK_DIR" || exit
sudo make -j"$(nproc)"
sudo dmesg -C

# parse config
if [ ! "$1" ]; then
    config_path="./config.example.json"
else 
    config_path="$1"
fi

config_json=$(cat "$config_path")

function get_modules_options () {
    echo "$config_json" | jq -r ".modules.$1"
}

function get_fs_options () {
    echo "$config_json" | jq -r ".fs.$1"
}


fs_init=$(get_fs_options init)
fs_meta_async=$(get_fs_options meta_async) 	  
fs_meta_local=$(get_fs_options meta_local) 	    
fs_meta_lfs=$(get_fs_options meta_lfs)
fs_meta_pack=$(get_fs_options meta_pack) 	    
fs_history_w=$(get_fs_options history_w) 	    
fs_wprotect=$(get_fs_options wprotect)	 

init_str=""

if (( fs_init == 1 )); then
    init_str+="init"
fi
if (( fs_meta_async != 0 )); then
    init_str+=",meta_async=$fs_meta_async"
fi
if (( fs_meta_local == 1 )); then
    init_str+=",meta_local"
fi
if (( fs_meta_pack == 1 )); then
    init_str+=",meta_pack"
fi
if (( fs_meta_lfs == 1 )); then
    init_str+=",meta_lfs"
fi
if (( fs_history_w == 1 )); then
    init_str+=",history_w"
fi
if (( fs_wprotect == 1 )); then
    init_str+=",wprotect"
fi

# inserting
echo "umounting..."
sudo umount $MNT_POINT

echo "Removing the old kernel module..."
sudo rmmod wofs > /dev/null 2>&1

echo "Inserting the new kernel module..."
sudo insmod wofs.ko \
    measure_timing="$(get_modules_options measure_timing)" \
    wprotect="$(get_modules_options wprotect)" \

sleep 1

echo "Mounting..."

sudo mount -t WOFS -o "$init_str" -o dax /dev/pmem0 $MNT_POINT
echo "Mount with configs: "
echo "$config_json" | jq
echo -e "$CLR_GREEN""> WOFS Mounted!""$CLR_END" 
cd "$ORIGINAL" || exit
