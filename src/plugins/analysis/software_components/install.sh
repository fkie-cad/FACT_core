#!/usr/bin/env bash

echo '-----------------------------------'
echo 'Installation of Software Components'
echo '-----------------------------------'

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

# build docker container
DOCKER_IMAGE=$(python3 -c "from internal.resolve_version_format_string import DOCKER_IMAGE; print(DOCKER_IMAGE)")
docker build -t "$DOCKER_IMAGE" docker || exit 1

# extract software names
python3 -c "from internal.extract_os_names import extract_names; extract_names()" || exit 1

exit 0
