#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )"

echo "------------------------------------"
echo "     install password cracker       "
echo "------------------------------------"

sudo -EH pip3 install --upgrade git+https://github.com/fkie-cad/common_helper_passwords.git

# installing JohnTheRipper
sudo apt-get install -y john
	
cd internal/passwords
wget -N https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt 
cd ..

python3 update_password_list.py

exit 0
