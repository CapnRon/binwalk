#!/bin/bash

set -x

# Needs ProgramStore to be on $PATH
# ProgramStore is from https://github.com/Broadcom/aeolus/blob/7acf337f602e381ca2288df9c5bf8ee81b4296d2/ProgramStore/ProgramStore.cpp
# It likely requires some changes to the Makefile, which makes some (invalid) assumptions

cd "$(dirname "$0")" || exit 1

tmp1=$(mktemp)
tmp2=$(mktemp)
trap 'rm -f "$tmp1" "$tmp2"' EXIT

echo "ProgramStore test image 1" > "$tmp1"
echo "ProgramStore test image 2" > "$tmp2"

# Fixed timestamp; parser requires >= 904608000 (1998-09-01 00:00:00 UTC)
ProgramStore -f "$tmp1" -o program_store.bin -t 1000000000 -c 0 -v 0001.0002 -d || exit $?

# Dual input files
ProgramStore -f "$tmp1" -f2 "$tmp2" -o program_store_dual.bin -t 1000000000 -c 4 -p 64 -v 0003.0004 -d || exit $?
