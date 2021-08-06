#!/usr/bin/env bash

echo '-----------------------------------'
echo 'Installation of Software Components'
echo '-----------------------------------'

# change cwd to this file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

# extract software names
python3 -c "from internal.extract_os_names import extract_names; extract_names()" || exit 1

exit 0
