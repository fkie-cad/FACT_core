#!/usr/bin/env bash

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" 

echo "------------------------------------"
echo " Installing shellcheck Plugin "
echo "------------------------------------"

sudo -EH apt install shellcheck

exit 0
