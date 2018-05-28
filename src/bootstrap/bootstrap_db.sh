#!/usr/bin/env bash

echo "####################################"
echo "#          installing db           #"
echo "####################################"

while [ "$1" != '' ]
  do
	[ "$1" == "xenial" ] && UBUNTU_XENIAL="yes" && echo "installing on Ubuntu 16.04" && shift
	[ "$1" == "bionic" ] && UBUNTU_BIONIC="yes" && echo "installing on Ubuntu 18.04" && shift
done

# change cwd to bootstrap dir
CURRENT_FILE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $CURRENT_FILE_DIR

echo "####################################"
echo "#       installing MongoDB         #"
echo "####################################"
if [ "$UBUNTU_XENIAL" == "yes" ]
then
	sudo -E apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 2930ADAE8CAF5059EE73BB4B58712A2291FA4AD5
	sudo rm /etc/apt/sources.list.d/mongodb-org-3.*
	echo "deb https://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.6 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.6.list
	sudo -E apt-get update
	sudo -E apt-get install -y mongodb-org
else
	sudo -E apt-get install -y mongodb
fi

echo "####################################"
echo "#       create directory           #"
echo "####################################"

factdbdir=$(grep -oP "dbPath:[\s]*\K[^\s]+" ../config/mongod.conf)
factuser=$(whoami)
factusergroup=$(id -gn)
sudo mkdir -p --mode=0744 $factdbdir 2> /dev/null
sudo chown $factuser:$factusergroup $factdbdir


echo "####################################"
echo "#  initializing DB authentication  #"
echo "####################################"
python3 ../init_database.py


echo "####################################"
echo "#           DB migration           #"
echo "####################################"
python3 ../migrate_database.py

cd ../../
rm start_fact_db
ln -s src/start_fact_db.py start_fact_db

exit 0