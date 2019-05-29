#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )" || { echo 'FAILED: Could not change into this directory!' ; exit 1; }

echo "------------------------------------"
echo "   install cve lookup dependencies  "
echo "------------------------------------"

sudo -EH pip3 install pyxdameraulevenshtein
python3 setup_repository

exit 0
