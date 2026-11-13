#!/usr/bin/env bash

set -e

# cd in this files directory for relative paths to work
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

FACTUSER=$(whoami)

echo "Installing pre-install requirements..."
sudo apt-get update
sudo apt-get -y install python3-dev git libffi-dev lsb-release build-essential jq curl
# build dependencies of FACT's core Python packages (ssdeep, python-magic)
sudo apt-get -y install libfuzzy-dev libmagic-dev

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
  CODENAME=trixie
elif [ -z "${CODENAME}" ]; then
  echo "Could not get distribution codename. Please make sure that your distribution is compatible to ubuntu/debian."
  exit 1
fi

echo "detected distro ${DISTRO} and codename ${CODENAME}"

supported_codenames=("jammy" "noble" "trixie" "kali-rolling")
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

echo "Installing Python dependencies with uv"
if ! command -v uv > /dev/null; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi
# install into the active venv if there is one, otherwise into uv's default .venv in the repository root
if [ -n "${VIRTUAL_ENV}" ]; then
  uv sync --locked --inexact --no-default-groups --active
else
  uv sync --locked --inexact --no-default-groups
  echo "Created venv $(realpath ../../.venv). Activate it before running install.py: . $(realpath ../../.venv)/bin/activate"
fi

echo -e "Pre-Install-Routine complete! \\033[31mPlease reboot before running install.py\\033[0m"

bash fix_executable_bits.sh

exit 0
