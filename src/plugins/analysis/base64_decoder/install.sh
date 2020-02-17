#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

echo "------------------------------------"
echo "     install base64 dependencies    "
echo "------------------------------------"

sudo -EH pip3 install git+https://github.com/armbues/python-entropy

exit 0