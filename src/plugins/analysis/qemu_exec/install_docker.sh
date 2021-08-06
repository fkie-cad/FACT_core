#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

# build docker container
if docker info > /dev/null 2>&1 ; then
    (cd docker && docker build --build-arg=http{,s}_proxy --build-arg=HTTP{,S}_PROXY -t fact/qemu:latest .) || exit 1
else
    echo "Error: docker daemon not running! Could not build docker image"
    exit 1
fi
