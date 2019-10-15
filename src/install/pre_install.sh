#!/usr/bin/env bash

FACTUSER=$(whoami)

CODENAME=$(lsb_release -cs)
if [ "${CODENAME}" = "tara" ] || [ "${CODENAME}" = "tessa" ] || [ "${CODENAME}" = "tina" ]; then
    CODENAME=bionic
elif [ "${CODENAME}" = "sarah" ] || [ "${CODENAME}" = "serena" ] || [ "${CODENAME}" = "sonya" ] || [ "${CODENAME}" = "sylvia" ]; then
    CODENAME=xenial
elif [ "${CODENAME}" = "rebecca" ] || [ "${CODENAME}" = "rafaela" ] || [ "${CODENAME}" = "rosa" ]; then
    CODENAME=trusty
    sudo apt-get -y install "linux-image-extra-$(uname -r)" linux-image-extra-virtual
fi

echo "Install Pre-Install Requirements"
sudo apt-get -y install python3-pip git libffi-dev

echo "Installing Docker"

# Uninstall old versions
sudo apt-get -y remove docker docker-engine docker.io

# Install packages to allow apt to use a repository over HTTPS
sudo apt-get -y install apt-transport-https ca-certificates curl software-properties-common

# Add Docker’s official GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

# set up the stable repository
if ! grep -q "^deb .*download.docker.com/linux/ubuntu" /etc/apt/sources.list /etc/apt/sources.list.d/*; then
    sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $CODENAME stable"
fi

# install docker
sudo apt-get update
sudo apt-get -y install docker-ce 
sudo systemctl enable docker

# add fact-user to docker group
if [ ! "$(getent group docker)" ]
then
    sudo groupadd docker
fi
sudo usermod -aG docker "$FACTUSER"

sudo -EH pip3 install --upgrade pip
sudo -EH pip3 install --upgrade docker-compose

echo "Installing Python Libraries for python based installation"
sudo -EH pip3 install --upgrade distro
sudo -EH pip3 install --upgrade python-magic

sudo -EH pip3 install --upgrade git+https://github.com/fkie-cad/common_helper_files.git
sudo -EH pip3 install --upgrade git+https://github.com/fkie-cad/common_helper_process.git

echo -e "Pre-Install-Routine complete! \033[31mPlease reboot before running install.py\033[0m"

exit 0
