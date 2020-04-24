#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

echo "------------------------------------"
echo "   install ip and uri coco modul    "
echo "------------------------------------"

sudo -EH pip3 install --upgrade git+https://github.com/fkie-cad/common_analysis_ip_and_uri.git || exit 1


echo "------------------------------------"
echo "           install GeoIP            "
echo "------------------------------------"

sudo -EH pip3 install --upgrade geoip2 || exit 1

if [ ! -e bin/GeoLite2-City/ ]
then
    echo "------------------------------------"
    echo "  Downloading Geolocation Database  "
    echo "------------------------------------"
    mkdir bin
    cd bin/ || exit 1
    wget https://github.com/codeqq/geolite2-city-mirror/raw/master/GeoLite2-City.tar.gz || exit 0
    mkdir GeoLite2-City
    tar xf GeoLite2-City.tar.gz -C GeoLite2-City --strip-components 1
    rm GeoLite2-City.tar.gz
else
    echo "Geolocation Database found. Skipping Download"
fi

exit 0
