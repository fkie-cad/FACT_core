#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )"

echo "------------------------------------"
echo "   install ip and uri coco modul    "
echo "------------------------------------"

sudo -EH pip3 install --upgrade git+https://github.com/fkie-cad/common_analysis_ip_and_uri.git


echo "------------------------------------"
echo "           install GeoIP            "
echo "------------------------------------"

sudo -EH pip3 install --upgrade geoip2

if [ -e bin/ ]
then
    sudo rm -R bin/
    echo "---------------------------------------------"
    echo " Updating Geolocation GeoLite2-city Database "
    echo "---------------------------------------------"
fi
mkdir bin
cd bin/
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz
mkdir GeoLite2-City && tar xf GeoLite2-City.tar.gz -C GeoLite2-City --strip-components 1
rm GeoLite2-City.tar.gz
exit 0
