#!/usr/bin/env bash

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

if [ "$1" = "fedora" ]
then
	echo "Installing shell linter..."
	sudo dnf install -y ShellCheck || exit 1

	echo " Installing lua linter..."
	sudo dnf install -y lua lua-devel luarocks || exit 1
	sudo luarocks install luafilesystem || exit 1
	sudo luarocks install argparse || exit 1
	sudo luarocks install luacheck || exit 1

	echo " Installing python linter..."
	sudo -EH pip3 install --upgrade pylint || exit 1

	echo " Installing javascript linter..."
	sudo dnf install -y nodejs npm
	sudo npm install -g jshint || exit 1

else
	echo "Installing shell linter..."
	sudo apt-get install -y shellcheck || exit 1

	echo " Installing lua linter..."
	sudo apt-get install -y luarocks lua5.3 liblua5.3-dev || exit 1
	sudo luarocks install luafilesystem || exit 1
	sudo luarocks install argparse || exit 1
	sudo luarocks install luacheck || exit 1

	echo " Installing python linter..."
	sudo -EH pip3 install --upgrade pylint || exit 1

	echo " Installing javascript linter..."
	sudo apt-get -y install npm || exit 1
	sudo npm install -g jshint || exit 1
fi

exit 0
