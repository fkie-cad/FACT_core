#!/usr/bin/env bash

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

echo "Installing shell linter..."
sudo dnf install -y ShellCheck || exit 1

echo " Installing lua linter..."
sudo dnf install -y lua || exit 1
sudo dnf install -y lua-devel || exit 1
sudo dnf install -y luarocks || exit 1

sudo luarocks install luafilesystem || exit 1
sudo luarocks install argparse || exit 1
sudo luarocks install luacheck || exit 1

echo " Installing python linter..."
sudo -EH pip3 install --upgrade pylint || exit 1

echo " Installing javascript linter..."
sudo dnf install -y nodejs npm
sudo npm install -g jshint || exit 1

exit 0
