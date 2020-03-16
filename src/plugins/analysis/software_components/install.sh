#!/usr/bin/env bash

echo '-----------------------------------'
echo 'Installation of Software Components'
echo '-----------------------------------'

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

# build docker container
docker build -t fact/format_string_resolver docker || exit 1

# extract software names
python3 -c "from internal.extract_os_names import extract_names; extract_names()" || exit 1

exit 0
