#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )"

echo "------------------------------------"
echo "          install ros_pack          "
echo "------------------------------------"

cd ../../../install

# get ros_pack source
git clone https://github.com/iam-TJ/ros_pack.git
# compile ros_pack
(cd ros_pack && make -j$(nproc) && cp ros_unpack ../../bin/)
rm -rf ros_pack

exit 0
