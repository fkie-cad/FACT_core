#!/usr/bin/env bash

echo '-----------------------------------'
echo 'Installation of Software Components'
echo '-----------------------------------'

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

# build docker container
docker build -t fact/fsr_ghidra_headless docker || exit 1

# extract software names
python3 extract_names.py || exit 1

exit 0
