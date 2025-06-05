#!/usr/bin/env bash

set -e

# cd in this files directory for relative paths to work
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

FACTUSER=$(whoami)

echo "Installing pre-install requirements..."
sudo apt-get update
sudo apt-get -y install python3-pip git libffi-dev lsb-release

# distro and codename detection
. /etc/os-release
if [ -n "${ID_LIKE}" ]; then
  if [ "${ID}" = "ubuntu" ]; then
    DISTRO="${ID}"
  else
    # ID_LIKE can contain multiple elements separated by spaces but we only want the first one
    DISTRO="${ID_LIKE%% *}"
  fi
else
  DISTRO="${ID}"
fi

if [ -z "${CODENAME}" ] && [ -n "${VERSION_CODENAME}" ]; then
  CODENAME="${VERSION_CODENAME}"
fi

if [ -n "${UBUNTU_CODENAME}" ]; then
  # this and DEBIAN_CODENAME are set for linux mint
  CODENAME="${UBUNTU_CODENAME}"
elif [ -n "${DEBIAN_CODENAME}" ]; then
  CODENAME="${DEBIAN_CODENAME}"
elif  [ "${CODENAME}" = "kali-rolling" ]; then
  CODENAME=bookworm
elif [ -z "${CODENAME}" ]; then
  echo "Could not get distribution codename. Please make sure that your distribution is compatible to ubuntu/debian."
  exit 1
fi

echo "detected distro ${DISTRO} and codename ${CODENAME}"

supported_codenames=("jammy" "noble" "bookworm" "trixie" "kali-rolling")
if [[ ! " ${supported_codenames[*]} " =~ ${CODENAME} ]]; then
    echo "Warning: your distribution is outdated or unsupported and the installation may not work as expected."
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
curl -fsSL "https://download.docker.com/linux/${DISTRO}/gpg" | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg --batch --yes
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

IS_VENV=$(python3 -c 'import sys; print(sys.exec_prefix!=sys.base_prefix)')
PREFIX=""
if [[ $IS_VENV == "False" ]]
then
  echo -e "\\033[31mWarning: It is highly discouraged to install FACT without a virtual environment because of the risk of conflicts with system Python packages!\\033[0m"
  PREFIX="sudo -EH python3 -m"
fi
$PREFIX pip install -U pip setuptools wheel
$PREFIX pip install -r ./requirements_pre_install.txt --prefer-binary

echo -e "Pre-Install-Routine complete! \\033[31mPlease reboot before running install.py\\033[0m"

exit 0
