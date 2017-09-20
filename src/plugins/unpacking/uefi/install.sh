#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )"

echo "------------------------------------"
echo "        install uefi parser         "
echo "------------------------------------"

cd ../../../bootstrap

git clone https://github.com/theopolis/uefi-firmware-parser.git
#(cd uefi-firmware-parser && git checkout db3230c41e9b1f1d1945788f047ba39a4b8daf2a) # - known stable commit
(cd uefi-firmware-parser && sudo -E python2 setup.py install --force && cp scripts/fv_parser.py ../../bin/)
sudo rm -rf uefi-firmware-parser

exit 0
