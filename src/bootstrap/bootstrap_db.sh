#!/usr/bin/env bash

echo "####################################"
echo "#          installing db           #"
echo "####################################"

# change cwd to bootstrap dir
CURRENT_FILE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $CURRENT_FILE_DIR

echo "####################################"
echo "#       installing MongoDB         #"
echo "####################################"
sudo -E apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 2930ADAE8CAF5059EE73BB4B58712A2291FA4AD5
sudo rm /etc/apt/sources.list.d/mongodb-org-3.*
echo "deb https://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.6 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.6.list
sudo -E apt update
sudo -E apt install -y mongodb-org
sudo -E apt upgrade -y


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