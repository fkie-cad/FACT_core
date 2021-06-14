#!/usr/bin/env bash

# change cwd to this file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

docker pull fkiecad/radare-web-gui:latest || exit 1

echo "Building docker container"
docker build -t input-vectors . || exit 1
