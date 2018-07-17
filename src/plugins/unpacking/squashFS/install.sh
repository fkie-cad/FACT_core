#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )"

echo "------------------------------------"
echo "   install additional sqfs tools    "
echo "------------------------------------"

sudo apt-get install -y libtool-bin libtool libacl1-dev libcap-dev libc6-dev-i386 lib32ncurses5-dev gcc-multilib lib32stdc++6 gawk pkg-config

mkdir bin
cd bin/
umask 0022
git clone https://github.com/Freetz/freetz.git
cd freetz
make -j$(nproc) tools
cp tools/unsquashfs4-avm-be tools/unsquashfs4-avm-le tools/unsquashfs3-multi ../
cd ..
rm -rf freetz

exit 0
