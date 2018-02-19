#!/usr/bin/env bash

echo "####################################"
echo "#       installing frontend        #"
echo "####################################"

while [ "$1" != '' ]
  do
	[ "$1" == "xenial" ] && UBUNTU_XENIAL="yes" && echo "installing on Ubuntu 16.04" && shift
    [ "$1" == "nginx" ] && NGINX="yes" && echo "installing nginx" && shift
done

# change cwd to bootstrap dir
CURRENT_FILE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $CURRENT_FILE_DIR

sudo -EH pip3 install --upgrade flask flask_restful flask_security flask-paginate Flask-API uwsgi

	
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


# ---- NGINX ----
if [ "$NGINX" = "yes" ]
then
	echo "####################################"
	echo "# installing and configuring nginx #"
	echo "####################################"
	sudo apt-get install -y nginx apache2-utils
	echo "generating a new certificate..."
	openssl genrsa -out faf.key 4096
	openssl req -new -key faf.key -out faf.csr
	openssl x509 -req -days 730 -in faf.csr -signkey faf.key -out faf.crt
	sudo mv faf.key faf.csr faf.crt /etc/nginx
	sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
	sudo rm /etc/nginx/nginx.conf
	(cd ../config && sudo ln -s $PWD/nginx.conf /etc/nginx/nginx.conf)
	sudo mkdir /etc/nginx/error
	(cd ../web_interface/templates/ && sudo ln -s $PWD/maintenance.html /etc/nginx/error/maintenance.html)
	echo "Please set a password for the default interface user (fact)"
	sudo htpasswd -c /etc/nginx/fact_htpasswd fact
	echo "Please set a password for the admin user (admin)"
	sudo htpasswd -c /etc/nginx/fact_admin_htpasswd admin
	sudo nginx -s reload
fi

cd ../../
rm start_fact_frontend
ln -s src/start_fact_frontend.py start_fact_frontend

exit 0
