#!/usr/bin/env bash

set -e

# cd in this files directory for relative paths to work
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

FACTUSER=$(whoami)

DISTRO=$(lsb_release -is)
if [ "${DISTRO}" = "Linuxmint" ] || [ "${DISTRO}" = "Ubuntu" ]; then
    DISTRO=ubuntu
elif [ "${DISTRO}" = "Kali" ] || [ "${DISTRO}" = "Debian" ]; then
    DISTRO=debian
fi

CODENAME=$(lsb_release -cs)
if [ "${CODENAME}" = "vanessa" ]; then
    CODENAME=jammy
elif [ "${CODENAME}" = "ulyana" ] || [ "${CODENAME}" = "ulyssa" ] || [ "${CODENAME}" = "uma" ] || [ "${CODENAME}" = "una" ]; then
    CODENAME=focal
elif [ "${CODENAME}" = "tara" ] || [ "${CODENAME}" = "tessa" ] || [ "${CODENAME}" = "tina" ] || [ "${CODENAME}" = "tricia" ]; then
    CODENAME=bionic
elif  [ "${CODENAME}" = "kali-rolling" ]; then
    CODENAME=buster
elif [ -z "${CODENAME}" ]; then
	echo "Could not get distribution codename. Please make sure that lsb-release is installed."
	exit 1
fi

echo "detected distro ${DISTRO} and codename ${CODENAME}"

echo "Install Pre-Install Requirements"
sudo apt-get update
sudo apt-get -y install python3-pip git libffi-dev

echo "Installing Docker"

# uninstall old docker versions
for i in docker docker-engine docker.io containerd runc; do
  sudo apt-get remove -y $i || true
done

# install prerequisites
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# add Docker's GPG key
sudo mkdir -p /etc/apt/keyrings
echo "curl -fsSL \"https://download.docker.com/linux/${DISTRO}/gpg\""
curl -fsSL "https://download.docker.com/linux/${DISTRO}/gpg" | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# set up repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${DISTRO} \
  ${CODENAME} stable" | sudo tee /etc/apt/sources.list.d/docker.list

# Install Docker Engine
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

sudo systemctl enable docker

# add fact-user to docker group
if [ ! "$(getent group docker)" ]
then
    sudo groupadd docker
fi
sudo usermod -aG docker "$FACTUSER"

IS_VENV=$(python3 -c 'import sys; print(sys.exec_prefix!=sys.base_prefix)')
SUDO=""
if [[ $IS_VENV == "False" ]]
then
  SUDO="sudo -EH"
fi
$SUDO pip3 install -U pip
$SUDO pip3 install -r ./requirements_pre_install.txt --prefer-binary

echo -e "Pre-Install-Routine complete! \\033[31mPlease reboot before running install.py\\033[0m"

exit 0
