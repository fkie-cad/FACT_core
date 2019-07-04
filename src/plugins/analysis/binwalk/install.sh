#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

echo "------------------------------------"
echo "    install binwalk dependencies    "
echo "------------------------------------"

sudo -EH apt-get install -y xvfb
sudo -EH pip3 install matplotlib cstruct==1.0 capstone

git clone https://github.com/dorpvom/binwalk.git
(
cd binwalk || return

python3 setup.py build
sudo -EH python3 setup.py install

cd .. 
)
sudo rm -rf binwalk

exit 0
