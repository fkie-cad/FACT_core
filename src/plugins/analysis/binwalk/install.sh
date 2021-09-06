#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

echo "------------------------------------"
echo "    install binwalk dependencies    "
echo "------------------------------------"

if [ "$1" = "fedora" ]
then 
	sudo -EH dnf install -y xorg-x11-server-Xvfb || exit 1
else
	sudo -EH apt-get install -y xvfb || exit 1
fi

sudo -EH pip3 install matplotlib cstruct==1.0 capstone || exit 1

git clone --single-branch https://github.com/ReFirmLabs/binwalk.git
(
    cd binwalk
    python3 setup.py build
    sudo -EH python3 setup.py install
) || exit 1
sudo rm -rf binwalk

exit 0
