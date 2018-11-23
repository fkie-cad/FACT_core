#!/usr/bin/env bash

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" 

echo "------------------------------------"
echo " Installing cwe_checker Plugin "
echo "------------------------------------"

echo "Checking out cwe_checker"
rm -fR internal
git clone https://github.com/fkie-cad/cwe_checker.git internal

echo "Cleaning up"
rm -rf internal/src/_build
rm -f internal/src/cwe_checker.plugin 

echo "Building docker container"
(cd internal && docker build --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy --build-arg HTTP_PROXY=$http_proxy --build-arg HTTPS_PROXY=$https_proxy -t cwe-checker .)

echo "Installing Python dependencies."
sudo -EH pip3 install sexpdata

exit 0
