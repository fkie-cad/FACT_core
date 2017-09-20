#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )"

echo "------------------------------------"
echo "         install jefferson          "
echo "------------------------------------"

sudo -EH pip2 install --upgrade cstruct==1.0
sudo -EH pip2 install --upgrade git+https://github.com/sviehb/jefferson.git

exit 0
