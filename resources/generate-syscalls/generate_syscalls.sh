#!/usr/bin/env bash

set -x

k_version="6.1.16"
k_link="https://cdn.kernel.org/pub/linux/kernel/v${k_version%%.*}.x/linux-${k_version}.tar.xz"

table="linux-${k_version}/arch/x86/entry/syscalls/syscall_64.tbl"
table_local="syscall.tbl"
out_file="syscalls.json"

if [ ! -d linux-${k_version} ];then
    curl $k_link > linux-${k_version}.tar.xz
    tar xvf linux-${k_version}.tar.xz
    ls -la linux-${k_version}
fi

if [ ! -f ${table} ]; then
	echo "$table doesn't exist"
	exit -1
fi

# Prepare tags
ctags --fields=afmikKlnsStz --c-kinds=+p -R linux-${k_version}

# Prepare table file
cp -v $table "$table_local"
sed -i '1,8d' "$table_local"
