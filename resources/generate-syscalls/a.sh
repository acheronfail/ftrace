#!/usr/bin/env bash

set -xe

out_file="syscalls.json"

# Generate JSON
./syscalls_from_tbl.py > $out_file

# ls -la .

# Clean up
rm -rf "/tmp/linux-${k_version}"
rm -rf "/tmp/linux-${k_version}.tar.xz"
# rm -rf tags
# rm -rf "$table_local"
sed -i "s/\/tmp\/linux-${k_version}\///g" $out_file