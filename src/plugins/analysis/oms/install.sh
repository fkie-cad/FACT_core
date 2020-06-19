#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

echo "------------------------------------"
echo "     install oms dependencies       "
echo "------------------------------------"

# common_analysis_oms
if [ "$1" = "fedora" ]
then 
	sudo dnf install -y clamav clamav-update || exit 1
else
	sudo apt-get install -y clamav clamav-daemon clamdscan || exit 1
fi
sudo -E freshclam

sudo -EH pip3 install --upgrade git+https://github.com/fkie-cad/common_analysis_oms.git || exit 1
	
exit 0
