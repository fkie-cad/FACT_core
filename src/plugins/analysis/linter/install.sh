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
if [[ $(lsb_release -c -s) == "xenial" ]]
then
    # xenial nodejs version is too old
    sudo apt-get install -y software-properties-common apt-transport-https curl || exit 1
    sudo add-apt-repository -y -r ppa:chris-lea/node.js || exit 1
    curl -sSL https://deb.nodesource.com/gpgkey/nodesource.gpg.key | sudo apt-key add -
    sudo rm -f /etc/apt/sources.list.d/chris-lea-node_js-*
    echo "deb https://deb.nodesource.com/node_14.x xenial main" | sudo tee /etc/apt/sources.list.d/nodesource.list
    echo "deb-src https://deb.nodesource.com/node_14.x xenial main" | sudo tee -a /etc/apt/sources.list.d/nodesource.list
    sudo apt-get update
    sudo apt-get -y install nodejs || exit 1
else
    sudo apt-get -y install npm || exit 1
fi
sudo npm install -g jshint || exit 1

exit 0
