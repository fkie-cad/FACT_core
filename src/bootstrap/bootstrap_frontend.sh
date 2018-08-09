#!/usr/bin/env bash

echo "####################################"
echo "#       installing frontend        #"
echo "####################################"

while [ "$1" != '' ]
  do
    [ "$1" == "xenial" ] && UBUNTU_XENIAL="yes" && echo "installing on Ubuntu 16.04" && shift
    [ "$1" == "bionic" ] && UBUNTU_BIONIC="yes" && echo "installing on Ubuntu 18.04" && shift
    [ "$1" == "nginx" ] && NGINX="yes" && echo "installing nginx" && shift
    [ "$1" == "radare" ] && RADARE="yes" && echo "installing radare binding" && shift
done

# change cwd to bootstrap dir
CURRENT_FILE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $CURRENT_FILE_DIR

sudo -EH pip3 install --upgrade flask flask_restful flask_security flask_sqlalchemy flask-paginate Flask-API uwsgi bcrypt

	
echo "######################################"
echo "#    installing web/js-frameworks    #"
echo "######################################"
cd ../web_interface/static
wget -nc https://github.com/twbs/bootstrap/releases/download/v3.3.7/bootstrap-3.3.7-dist.zip
unzip -o bootstrap-3.3.7-dist.zip
rm bootstrap-3.3.7-dist.zip
rm -rf bootstrap
mv bootstrap-3.3.7-dist bootstrap
cd bootstrap/css
rm bootstrap.min.css bootstrap.min.css.map bootstrap-theme.min.css bootstrap-theme.min.css.map bootstrap.css.map bootstrap-theme.css.map
patch --forward -r - bootstrap.css ../../../../bootstrap/patches/bootstrap.patch
patch --forward -r - bootstrap-theme.css ../../../../bootstrap/patches/bootstrap-theme.patch
cd ../js
# download jquery
wget -nc https://ajax.googleapis.com/ajax/libs/jquery/1.12.0/jquery.min.js
# bootstrap date picker
wget -nc https://raw.githubusercontent.com/Eonasdan/bootstrap-datetimepicker/master/build/js/bootstrap-datetimepicker.min.js
wget -nc https://raw.githubusercontent.com/moment/moment/develop/moment.js
cd ../css
wget -nc https://raw.githubusercontent.com/Eonasdan/bootstrap-datetimepicker/master/build/css/bootstrap-datetimepicker.min.css
cd ../../
# x-editable
if [ ! -d "bootstrap3-editable" ]; then
    wget https://vitalets.github.io/x-editable/assets/zip/bootstrap3-editable-1.5.1.zip
    unzip -o bootstrap3-editable-1.5.1.zip
    rm bootstrap3-editable-1.5.1.zip CHANGELOG.txt LICENSE-MIT README.md
    rm -rf inputs-ext
fi
# download jstree
if [ -d "jstree" ]; then
  rm -r jstree
fi
wget -nc https://github.com/vakata/jstree/zipball/3.3.2
unzip 3.3.2
rm 3.3.2
mv vakata* jstree
# download angularJS
wget -nc https://ajax.googleapis.com/ajax/libs/angularjs/1.4.8/angular.min.js
# download charts.js
wget -nc https://github.com/chartjs/Chart.js/releases/download/v2.3.0/Chart.js
cd ../../bootstrap


echo "####################################"
echo "#       create user database       #"
echo "####################################"

cd ../
echo "from helperFunctions.config import load_config;config = load_config('main.cfg');dburi=config.get('data_storage', 'user_database');print('/'.join(dburi.split('/')[:-1])[10:]);exit(0)" > get_sqlite_dir_name.py

cd ..
factauthdir=$(python3 src/get_sqlite_dir_name.py)
factuser=$(whoami)
factusergroup=$(id -gn)
sudo mkdir -p --mode=0744 $factauthdir 2> /dev/null
sudo chown $factuser:$factusergroup $factauthdir
rm src/get_sqlite_dir_name.py
cd src/bootstrap


# ---- NGINX ----
if [ "$NGINX" = "yes" ]
then
	echo "####################################"
	echo "# installing and configuring nginx #"
	echo "####################################"
	sudo apt-get install -y nginx
	echo "generating a new certificate..."
	openssl genrsa -out fact.key 4096
	openssl req -new -key fact.key -out fact.csr
	openssl x509 -req -days 730 -in fact.csr -signkey fact.key -out fact.crt
	sudo mv fact.key fact.csr fact.crt /etc/nginx
	sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
	sudo rm /etc/nginx/nginx.conf
	(cd ../config && sudo ln -s $PWD/nginx.conf /etc/nginx/nginx.conf)
	sudo mkdir /etc/nginx/error
	(cd ../web_interface/templates/ && sudo ln -s $PWD/maintenance.html /etc/nginx/error/maintenance.html)
	sudo nginx -s reload
fi


# ---- RADARE ----
if [ "$RADARE" = "yes" ]
then
	echo "####################################"
	echo "# installing and configuring nginx #"
	echo "####################################"
    if [ -x "$(command -v docker-compose)" ]; then 
        echo "Initiializing docker container for radare"
        cd radare
        docker-compose build
        cd ..
    else
        printf "\n [ERROR] docker-compose is not installed. Please (re-)run pre_install.sh !\n"
    fi
fi


cd ../../
rm start_fact_frontend
ln -s src/start_fact_frontend.py start_fact_frontend

exit 0
