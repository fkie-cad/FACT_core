#!/usr/bin/env bash

set -e

# === CLI arguments and help ===
# defaults:
SKIP_DOCKER=false
SILENT=false

show_help() {
    cat << EOF
$(basename "$0") is a script for installing the installation requirements of
FACT and should be run before running "python3 install.py".
Usage: $(basename "$0") [OPTIONS]

Options:
    -D, --skip-docker  Skip Docker installation
    -d, --debug        Show debugging output
    -s, --silent       No CLI output
    -h, --help         Show this help
EOF
}

log() {
  if [[ "$SILENT" == true ]]; then
    echo "$@"
  fi
}

# parse CLI arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -D|--skip-docker)
            SKIP_DOCKER=true
            shift
            ;;
        -s|--silent)
            SILENT=true
            shift
            ;;
        -d|--debug)
            set -x
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            show_help
            exit 1
            ;;
    esac
done

# cd in this files directory for relative paths to work
cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

FACTUSER=$(whoami)

log "Installing pre-install requirements..."

# === step 1: apt packages ===
sudo apt-get update
grep -vE '^\s*(#|$)' apt-pkgs-pre_install.txt | sudo xargs apt-get install -y

# === step 2: distro and codename detection ===
DISTRO=$(lsb_release -is)
if [ "${DISTRO}" = "Linuxmint" ] || [ "${DISTRO}" = "Ubuntu" ]; then
    DISTRO=ubuntu
elif [ "${DISTRO}" = "Kali" ] || [ "${DISTRO}" = "Debian" ]; then
    DISTRO=debian
fi

CODENAME=$(lsb_release -cs)
if [ "${CODENAME}" = "wilma" ] || [ "${CODENAME}" = "xia" ] || [ "${CODENAME}" = "zara" ]; then
    CODENAME=noble
elif [ "${CODENAME}" = "vanessa" ] || [ "${CODENAME}" = "vera" ] || [ "${CODENAME}" = "victoria" ] || [ "${CODENAME}" = "virginia" ]; then
    CODENAME=jammy
elif [ "${CODENAME}" = "ulyana" ] || [ "${CODENAME}" = "ulyssa" ] || [ "${CODENAME}" = "uma" ] || [ "${CODENAME}" = "una" ]; then
    CODENAME=focal
elif  [ "${CODENAME}" = "kali-rolling" ]; then
    CODENAME=bookworm
elif [ -z "${CODENAME}" ]; then
	echo "Could not get distribution codename. Please make sure that your distribution is compatible to ubuntu/debian." >&2
	exit 1
fi

log "detected distro ${DISTRO} and codename ${CODENAME}"

if [ "${CODENAME}" = "bionic" ] || [ "${CODENAME}" = "focal" ] || [ "${CODENAME}" = "buster" ] || [ "${CODENAME}" = "bullseye" ]; then
  log "Warning: your distribution is outdated and the installation may not work as expected. Please upgrade your OS."
fi

# === step 3: docker installation ===
if [[ "$SKIP_DOCKER" == false ]]; then
  # docker installation (source: https://docs.docker.com/engine/install/{ubuntu|debian})
  log "Installing Docker"

  # uninstall old docker versions
  sudo apt-get remove -y "$(dpkg --get-selections docker.io docker-compose docker-compose-v2 docker-doc podman-docker containerd runc | cut -f1)"

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
else
    log "Skipping Docker installation"
fi

# === step 4: python packages ===
IS_VENV=$(python3 -c 'import sys; print(sys.exec_prefix!=sys.base_prefix)')
PREFIX=""
if [[ $IS_VENV == "False" ]]
then
  log -e "\\033[31mWarning: It is highly discouraged to install FACT without a virtual environment because of the risk of conflicts with system Python packages!\\033[0m"
  PREFIX="sudo -EH python3 -m"
fi
$PREFIX pip install -U pip setuptools wheel
$PREFIX pip install -r ./requirements_pre_install.txt --prefer-binary

log -e "Pre-Install-Routine complete! \\033[31mPlease make sure you can run docker containers (e.g. reboot) before running install.py\\033[0m"

exit 0
