#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )"

echo "------------------------------------"
echo "        install uefi parser         "
echo "------------------------------------"

cd ../../../install

git clone https://github.com/theopolis/uefi-firmware-parser.git
cd uefi-firmware-parser
git checkout d48d6b9627ed559f14b703f4146fb92315ed5a92 # known stable commit
sudo -E python2 setup.py install --force
cp bin/uefi-firmware-parser ../../bin
cd ..
sudo rm -rf uefi-firmware-parser

exit 0
