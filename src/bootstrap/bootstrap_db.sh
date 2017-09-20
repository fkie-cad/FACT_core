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
sudo -E apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 0C49F3730359A14518585931BC711F9BA15703C6
echo "deb http://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.2.list
sudo -E apt-get update
sudo -E apt-get install -y mongodb-org


echo "####################################"
echo "#       create directory           #"
echo "####################################"

fafdbdir=$(grep -oP "dbPath:[\s]*\K[^\s]+" ../config/mongod.conf)
fafuser=$(whoami)
fafusergroup=$(id -gn)
sudo mkdir -p --mode=0744 $fafdbdir 2> /dev/null
sudo chown $fafuser:$fafusergroup $fafdbdir


echo "####################################"
echo "#  initializing DB authentication  #"
echo "####################################"
python3 ../init_database.py


echo "####################################"
echo "#           DB migration           #"
echo "####################################"
python3 ../migrate_database.py

cd ../../
ln -s src/start_faf_db.py start_fact_db

exit 0