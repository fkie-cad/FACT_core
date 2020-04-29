#!/usr/bin/env bash

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )"  || exit 1

echo "Installing shell linter..."
sudo apt-get install -y shellcheck || exit 1

echo " Installing lua linter..."
sudo apt-get install -y luarocks || exit 1
sudo luarocks install luafilesystem || exit 1
sudo luarocks install argparse || exit 1
sudo luarocks install luacheck || exit 1

echo " Installing python linter..."
sudo -EH pip3 install --upgrade pylint || exit 1

echo " Installing javascript linter..."
sudo apt-get install -y libssl1.0-dev nodejs-dev node-gyp npm || exit 1
sudo npm install -g jshint || exit 1

exit 0
