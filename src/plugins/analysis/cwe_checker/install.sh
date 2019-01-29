#!/usr/bin/env bash

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" 

echo "------------------------------------"
echo " Installing cwe_checker Plugin "
echo "------------------------------------"

echo "Trying to pull cwe_checker Docker image"
docker pull fkiecad/cwe_checker:latest
return_code=$?

if [[ ${return_code} -eq 0 ]]; then
    echo "Docker pull successfull"
else
    echo "Docker pull failed. Installing cwe_checker from git"

    echo "Checking out cwe_checker"
    rm -fR internal
    git clone https://github.com/fkie-cad/cwe_checker.git internal

    echo "Cleaning up"
    rm -rf internal/src/_build
    rm -f internal/src/cwe_checker.plugin

    echo "Building docker container"
    (cd internal && docker build --build-arg=http{,s}_proxy --build-arg=HTTP{,S}_PROXY -t cwe-checker .)
fi

echo "Installing Python dependencies."
sudo -EH pip3 install sexpdata

exit 0
