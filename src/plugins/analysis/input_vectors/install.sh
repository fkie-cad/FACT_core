#!/usr/bin/env bash

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" 

echo "------------------------------------"
echo " Installing input_vectors Plugin "
echo "------------------------------------"

echo "Building docker container"
docker build -t input-vectors .

exit 0
