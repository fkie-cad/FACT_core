#!/usr/bin/env bash

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

docker build -t fs_metadata_mounting docker || exit 1

exit 0
