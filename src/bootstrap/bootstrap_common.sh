#!/usr/bin/env bash

echo "####################################"
echo "#     Update Operating System      #"
echo "####################################"

while [ "$1" != '' ]
  do
	[ "$1" == "xenial" ] && UBUNTU_XENIAL="yes" && echo "installing on Ubuntu 16.04" && shift
	[ "$1" == "bionic" ] && UBUNTU_BIONIC="yes" && echo "installing on Ubuntu 18.04" && shift
done

sudo apt-get install -y apt-transport-https
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get autoremove -y
sudo apt-get clean

echo "####################################"
echo "#  installing general dependencies #"
echo "####################################"


# change cwd to bootstrap dir
CURRENT_FILE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $CURRENT_FILE_DIR


# update submodules
(cd ../../ && git submodule foreach 'git pull')


# make bin dir
mkdir ../bin

# set failsafe ssh environment for git
export GIT_SSH_COMMAND="ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

# install python3 and general build stuff
sudo apt-get install -y python3 python3-dev build-essential automake autoconf libtool git unzip
if [ "$UBUNTU_BIONIC" == "yes" ]
then
	sudo -EH pip3 install testresources
fi
# get a bugfree recent pip version
sudo apt-get remove -y python3-pip python3-setuptools python3-wheel
sudo apt-get autoremove -y
wget https://bootstrap.pypa.io/get-pip.py
sudo -EH python3 get-pip.py
rm get-pip.py

# install python2
sudo apt-get install -y python python-dev
sudo apt-get remove -y python-pip
sudo apt-get autoremove -y
wget https://bootstrap.pypa.io/get-pip.py
sudo -EH python2 get-pip.py
rm get-pip.py


# install general python dependencys
sudo apt-get install -y libmagic-dev libffi-dev libfuzzy-dev
sudo -EH pip3 install psutil
sudo -EH pip3 install --upgrade pytest==3.5.1 pytest-cov pytest-pep8 pylint python-magic xmltodict yara-python==3.7.0 appdirs
sudo -EH pip3 install --upgrade ssdeep
sudo -EH pip3 install --upgrade lief

# install python mongo bindings
sudo -EH pip3 install --upgrade pymongo pyyaml

# ---- VarietyJS used for advanced search map generation ----
# is executed by update_statistic.py
git clone https://github.com/variety/variety.git
cd variety/
git checkout 2f4d815
mv -f variety.js ../../bin
mv -f spec ../../bin/
cd ..
rm -rf variety
	
echo "####################################"
echo "#  installing common code modules  #"
echo "####################################"

# common_helper_files
sudo -EH pip3 install hurry.filesize
sudo -EH pip3 install --upgrade git+https://github.com/fkie-cad/common_helper_files.git
# common_helper_mongo
sudo -EH pip3 install --upgrade git+https://github.com/fkie-cad/common_helper_mongo.git
# common_helper_encoder
sudo -EH pip3 install --upgrade git+https://github.com/mass-project/common_helper_encoder.git
# common_helper_filter
sudo -EH pip3 install --upgrade git+https://github.com/fkie-cad/common_helper_filter.git


echo "####################################"
echo "#       install start script       #"
echo "####################################"
cd ../../
rm start_all_installed_fact_components
ln -s src/start_fact.py start_all_installed_fact_components

exit 0

