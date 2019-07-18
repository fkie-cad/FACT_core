#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )" || { echo 'FAILED: Could not change into this directory!' ; exit 1; }

echo "------------------------------------"
echo "   install cve lookup dependencies  "
echo "------------------------------------"

sudo -EH pip3 install pyxdameraulevenshtein

#
# setup_repository.py can be called with arguments specified by the user (call setup_repository.py -h for more info)
# however, for the initial start, it is recommended to use the given default values
# to ensure the full functionality of the plugin.
#

(
cd internal || exit
if [ -e "cve_cpe.db" ]
then
	echo "Updating existing database"
	python3 setup_repository.py --update true
else
	echo "Setting up database"
	python3 setup_repository.py
fi
)

exit 0
