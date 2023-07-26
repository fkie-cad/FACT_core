#!/usr/bin/env bash

set -e

# cd in this files directory for relative paths to work
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

FACTUSER=$(whoami)

echo "Installing pre-install requirements..."
sudo apt-get update
sudo apt-get -y install python3-pip git libffi-dev lsb-release

# distro and codename detection
DISTRO=$(lsb_release -is)
if [ "${DISTRO}" = "Linuxmint" ] || [ "${DISTRO}" = "Ubuntu" ]; then
    DISTRO=ubuntu
elif [ "${DISTRO}" = "Kali" ] || [ "${DISTRO}" = "Debian" ]; then
    DISTRO=debian
fi

CODENAME=$(lsb_release -cs)
if [ "${CODENAME}" = "vanessa" ] || [ "${CODENAME}" = "vera" ] || [ "${CODENAME}" = "victoria" ] ; then
    CODENAME=jammy
elif [ "${CODENAME}" = "ulyana" ] || [ "${CODENAME}" = "ulyssa" ] || [ "${CODENAME}" = "uma" ] || [ "${CODENAME}" = "una" ]; then
    CODENAME=focal
elif  [ "${CODENAME}" = "kali-rolling" ]; then
    CODENAME=bookworm
elif [ -z "${CODENAME}" ]; then
	echo "Could not get distribution codename. Please make sure that your distribution is compatible to ubuntu/debian."
	exit 1
fi

echo "detected distro ${DISTRO} and codename ${CODENAME}"

if [ "${CODENAME}" = "bionic" ] || [ "${CODENAME}" = "xenial" ] || [ "${CODENAME}" = "buster" ]; then
  echo "Warning: your distribution is outdated and the installation may not work as expected. Please upgrade your OS."
fi

# docker installation (source: https://docs.docker.com/engine/install/{ubuntu|debian})
echo "Installing Docker"

# uninstall old docker versions
for i in docker.io docker-doc docker-compose podman-docker containerd runc; do
  sudo apt-get remove -y $i || true
done

# install prerequisites
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg

# add Docker's GPG key
sudo install -m 0755 -d /etc/apt/keyrings
echo "curl -fsSL \"https://download.docker.com/linux/${DISTRO}/gpg\""
curl -fsSL "https://download.docker.com/linux/${DISTRO}/gpg" | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# set up repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${DISTRO} \
  ${CODENAME} stable" | sudo tee /etc/apt/sources.list.d/docker.list

# Install Docker Engine
sudo apt-get update
sudo apt-get -o Dpkg::Options::="--force-confnew" install -y \
  docker-ce \
  docker-ce-cli \
  containerd.io \
  docker-buildx-plugin \
  docker-compose-plugin

sudo systemctl enable docker

# add fact-user to docker group
if [ ! "$(getent group docker)" ]
then
    sudo groupadd docker
fi
sudo usermod -aG docker "$FACTUSER"

# Setup npm repository as described in https://github.com/nodesource/distributions/blob/master/README.md#debinstall
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -

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
