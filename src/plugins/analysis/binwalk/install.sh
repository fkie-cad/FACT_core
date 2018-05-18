#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )"

echo "------------------------------------"
echo "    install binwalk dependencies    "
echo "------------------------------------"

sudo -EH apt-get install -y xvfb

exit 0
