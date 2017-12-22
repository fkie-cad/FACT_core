#!/usr/bin/env bash

echo "####################################"
echo "#       installing backend         #"
echo "####################################"

# change cwd to bootstrap dir
CURRENT_FILE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $CURRENT_FILE_DIR

# dependencies
sudo apt-get install -y python-dev python-setuptools
sudo apt-get install -y libjpeg-dev liblzma-dev liblzo2-dev zlib1g-dev
sudo apt-get install -y libssl-dev python3-tk
sudo -EH pip3 install --upgrade pluginbase Pillow cryptography pyopenssl entropy matplotlib
	
sudo -E apt-get install -y python-pip
# removes due to compatibilty reasons
sudo -E apt-get remove -y python-lzma
sudo -EH pip2 uninstall -y pyliblzma
sudo -E apt-get install -y python-lzma

# install yara
sudo apt-get install -y bison flex libmagic-dev
wget https://github.com/VirusTotal/yara/archive/v3.6.3.zip
unzip v3.6.3.zip
cd yara-3.*
#patch --forward -r - libyara/arena.c ../patches/yara.patchfile 
chmod +x bootstrap.sh
./bootstrap.sh
./configure --enable-magic
make
sudo make install
# CAUTION: Yara python binding is installed in bootstrap_common, because it is needed in the frontend as well.
cd ..
sudo rm -fr yara* v3.6.3.zip


echo "####################################"
echo "#       installing unpacker        #"
echo "####################################"

sudo apt-get install -y fakeroot


# ---- sasquatch unpacker ----
git clone https://github.com/devttys0/sasquatch
(cd sasquatch && ./build.sh)
rm -fr sasquatch

# ubi_reader
sudo -EH pip2 install --upgrade python-lzo
git clone https://github.com/jrspruitt/ubi_reader
(cd ubi_reader && sudo python2 setup.py install --force)
sudo rm -fR ubi_reader


# ---- binwalk ----
sudo apt-get install -y libqt4-opengl python3-opengl python3-pyqt4 python3-pyqt4.qtopengl mtd-utils gzip bzip2 tar arj lhasa p7zip cabextract cramfsprogs cramfsswap squashfs-tools zlib1g-dev liblzma-dev liblzo2-dev liblzo2-dev xvfb
sudo apt-get install -y libcapstone3 libcapstone-dev
sudo -EH pip3 install --upgrade pyqtgraph capstone cstruct python-lzo numpy scipy
git clone https://github.com/sviehb/jefferson
(cd jefferson && sudo python3 setup.py install)
sudo rm -fr jefferson
wget -O - http://my.smithmicro.com/downloads/files/stuffit520.611linux-i386.tar.gz | tar -zxv
sudo cp bin/unstuff /usr/local/bin/
rm -fr bin doc man

# ---- patch pyqtgraph ----
sudo patch --forward -r - /usr/local/lib/python3.5/dist-packages/pyqtgraph/exporters/ImageExporter.py patches/qt_patchfile

git clone https://github.com/devttys0/binwalk.git
(cd binwalk && sudo python3 setup.py install --force)
sudo rm -fr binwalk

# ---- patool and unpacking backends ----
sudo -EH pip2 install --upgrade patool
sudo -EH pip3 install --upgrade patool

# ubuntu 14.04
sudo apt-get install -y openjdk-7-jdk
# ubuntu 16.04
sudo apt-get install -y openjdk-8-jdk

sudo apt-get install -y lrzip cpio unadf rpm2cpio lzop lhasa cabextract zpaq archmage arj xdms rzip lzip unalz unrar unzip gzip nomarch flac unace zoo sharutils
sudo apt-get install -y unar

# ---- firmware-mod-kit ----
git clone https://github.com/rampageX/firmware-mod-kit.git
(cd firmware-mod-kit/src && sh configure && make)
cp firmware-mod-kit/src/yaffs2utils/unyaffs2 firmware-mod-kit/src/untrx firmware-mod-kit/src/tpl-tool/src/tpl-tool ../bin/
rm -rf firmware-mod-kit


echo "####################################"
echo "#  installing common code modules  #"
echo "####################################"


# common_helper_subprocess
sudo -EH pip3 install --upgrade git+https://github.com/fkie-cad/common_helper_process.git
# common_helper_yara
sudo -EH pip3 install --upgrade git+https://github.com/fkie-cad/common_helper_yara.git
# common_helper_unpacking_classifier
sudo -EH pip3 install --upgrade git+https://github.com/fkie-cad/common_helper_unpacking_classifier.git
# common_analysis_base
sudo -EH pip3 install --upgrade git+https://github.com/mass-project/common_analysis_base.git

echo "####################################"
echo "#   install plug-in dependencies   #"
echo "####################################"

set ../plugins/*/*/install.sh

while [ "$1" != '' ]
  do
	( exec $1 ) && shift    
done


echo "####################################"
echo "#    compile custom magic file     #"
echo "####################################"
cat ../mime/custom_* > ../mime/custommime
(cd ../mime && file -C -m custommime && mv custommime.mgc ../bin/)
rm ../mime/custommime

echo "######################################"
echo "#       configure environment        #"
echo "######################################"
echo "add rules to sudo..."
# Insert additional changes to the sudoers file by applying the syntax used below
CURUSER=$(whoami 2>&1)
printf "$CURUSER\tALL=NOPASSWD: /bin/mount \n\
$CURUSER\tALL=NOPASSWD: /bin/umount \n\
$CURUSER\tALL=NOPASSWD: /usr/local/bin/sasquatch \n\
$CURUSER\tALL=NOPASSWD: /bin/rm \n\
$CURUSER\tALL=NOPASSWD: /bin/cp \n\
$CURUSER\tALL=NOPASSWD: /bin/mknod \n\
$CURUSER\tALL=NOPASSWD: /bin/dd \n\
$CURUSER\tALL=NOPASSWD: /bin/chown\n" > /tmp/faf_overrides
sudo chown root:root /tmp/faf_overrides
sudo mv /tmp/faf_overrides /etc/sudoers.d/faf_overrides

echo "set environment variables..."
sudo cp -f fact_env.sh /etc/profile.d/
sudo chmod 755 /etc/profile.d/fact_env.sh
source /etc/profile

echo "####################################"
echo "#       create directories         #"
echo "####################################"

cd ../
echo "from helperFunctions.config import load_config;config = load_config('main.cfg');print(config.get('data_storage', 'firmware_file_storage_directory'));exit(0)" > get_data_dir_name.py
cd ..
fafdatadir=$(python3 src/get_data_dir_name.py)
fafuser=$(whoami)
fafusergroup=$(id -gn)
sudo mkdir -p --mode=0744 $fafdatadir 2> /dev/null
sudo chown $fafuser:$fafusergroup $fafdatadir 
rm src/get_data_dir_name.py
cd src/bootstrap

echo "####################################"
echo "#    compiling yara signatures     #"
echo "####################################"
python3 ../compile_yara_signatures.py
#compile test signatures
yarac -d test_flag=false ../test/unit/analysis/test.yara ../analysis/signatures/Yara_Base_Plugin.yc


echo "####################################"
echo "# populating backend installation  #"
echo "####################################"
cd ../../
rm start_fact_backend
ln -s src/start_fact_backend.py start_fact_backend

exit 0
