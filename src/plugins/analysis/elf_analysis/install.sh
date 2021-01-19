#!/usr/bin/env bash

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

echo " Installing behavior tagging Plugin "
# FIXME: nightly build to fix install bug
sudo -EH pip3 install -U --index-url  https://lief-project.github.io/packages lief || exit 1

exit 0
