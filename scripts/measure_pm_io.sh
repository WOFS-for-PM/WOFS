#!/usr/bin/env bash

function get_pmem_id_by_name() {
    local pmem_name="$1"
    local number=$pmem_name
    number=${number//pmem/}
    number=$((number+1))
    if ! sudo ipmctl show -performance | grep "DimmID=" | sed -n "$number""p" | sed 's/---//g' | sed 's/DimmID=//g'; then
        echo "Error: Cannot get pmem${number} id. Did you active pmem${number}?"
        exit 1
    fi
}

function measure_start() {
    local pmem_id="$1"
    res1=$(mktemp)
    sudo ipmctl show -dimm "$pmem_id" -performance | grep TotalMedia | awk -F= '{print $1,$2}' | sed 's/.*Total//g' >$res1
}

function measure_end() {
    local pmem_id="$1"
    res2=$(mktemp)
    sudo ipmctl show -dimm "$pmem_id" -performance | grep TotalMedia | awk -F= '{print $1,$2}' | sed 's/.*Total//g' >$res2
    paste "$res1" "$res2" | awk --non-decimal-data '{print $1,($4-$2)*64}'
}
