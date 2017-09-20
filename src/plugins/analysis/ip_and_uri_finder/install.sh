#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )"

echo "------------------------------------"
echo "   install ip and uri coco modul    "
echo "------------------------------------"

sudo -EH pip3 install --upgrade git+https://github.com/fkie-cad/common_analysis_ip_and_uri.git

exit 0
