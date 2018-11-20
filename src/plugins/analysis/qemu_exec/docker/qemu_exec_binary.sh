#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Usage: qemu_exec_binary.sh ARCH PATH_TO_BINARY";
    exit 1
fi

docker run fact/firmware-qemu-exec:latest $1 $@
