#!/bin/bash

FIRMWARE_ROOT=/opt/firmware_root
ARCH=$1
FILE_PATH=$2

# Options
for option in "-h" "--help" "-help" "--version" " "; do
    timeout 1s qemu-${ARCH} ${FIRMWARE_ROOT}${FILE_PATH} ${option} > stdout_log 2> stderr_log
    echo "$?" > return_code_log

    echo "§#§option§#§"${option}"§#§"
    echo "§#§stdout§#§"$(cat stdout_log)"§#§"
    echo "§#§stderr§#§"$(cat stderr_log)"§#§"
    echo "§#§return_code§#§"$(cat return_code_log)"§#§"
done

# strace
timeout 2s qemu-${ARCH} -strace ${FIRMWARE_ROOT}${FILE_PATH} > stdout_log 2> stderr_log
echo "§#§strace§#§"
echo "§#§stdout§#§"$(cat stdout_log)"§#§"
echo "§#§stderr§#§"$(cat stderr_log)"§#§"

exit 0
