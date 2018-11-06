#!/usr/bin/env bash

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" 

echo "Installing shell linter..."
sudo -EH apt install shellcheck

echo " Installing lua linter ..."
sudo apt install -y luarocks
sudo luarocks install luacheck

echo " Installing python linter..."
sudo -EH pip3 install --upgrade pylint

echo " Installing javascript linter..."
sudo apt-get install -y nodejs
sudo npm install -g jshint

exit 0
