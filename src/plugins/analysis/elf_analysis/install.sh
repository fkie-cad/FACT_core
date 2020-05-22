#!/usr/bin/env bash

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

echo " Installing behavior tagging Plugin "
sudo -EH pip3 install --upgrade lief || exit 1

exit 0
