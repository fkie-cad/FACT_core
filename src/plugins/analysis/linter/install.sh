#!/usr/bin/env bash

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" 

echo "Installing shell linter..."
sudo apt-get install -y shellcheck

echo " Installing lua linter ..."
sudo apt-get install -y luarocks
sudo luarocks install luafilesystem
sudo luarocks install argparse
sudo luarocks install luacheck

echo " Installing python linter..."
sudo -EH pip3 install --upgrade pylint

echo " Installing javascript linter..."
sudo apt-get install -y libssl1.0-dev
sudo apt-get install -y nodejs-dev
sudo apt-get install -y node-gyp
sudo apt-get install -y npm
sudo npm install -g jshint

exit 0
