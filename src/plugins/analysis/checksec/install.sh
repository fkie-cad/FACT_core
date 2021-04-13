#!/usr/bin/env bash

# change cwd to current file's directory
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

echo "------------------------------------"
echo "        Install checksec.sh        "
echo "------------------------------------"

rm -rf shell_skript
git clone https://github.com/slimm609/checksec.sh.git shell_skript || exit 1
	
exit 0