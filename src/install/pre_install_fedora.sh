#!/usr/bin/env bash

FACTUSER=$(whoami)

sudo dnf install -y redhat-lsb
sudo dnf install -y grubby

CODENAME=$(lsb_release -cs)
if [ "${CODENAME}" = "ThirtyOne" ]; then
  CODENAME=ThirtyOne
elif [ "${CODENAME}" = "ThirtyTwo" ]; then
  CODENAME=ThirtyOne
fi

echo "Install Pre-Install Requirements"

sudo dnf install -y python3-pip
sudo dnf install -y git
sudo dnf install -y libffi-devel
sudo dnf install -y ca-certificates
sudo dnf install -y curl

echo "Installing Docker"

if [ "${CODENAME}" = "ThirtyOne" ]; then
  sudo dnf -y install dnf-plugins-core
  sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo

  sudo dnf config-manager --set-disabled docker-ce-nightly
  sudo dnf config-manager --set-disabled docker-ce-test

  sudo dnf install -y docker-ce docker-ce-cli containerd.io

  sudo grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=0"

elif [ "${CODENAME}" = "ThirtyTwo" ]; then
  echo "NO SUPPORT YET"
  exit 1
fi

sudo systemctl start docker
sudo systemctl enable docker

echo "Adding mongodb repo" >> /etc/yum.repos.d/mongodb.repo
echo "[mongodb-org-4.2]" >> /etc/yum.repos.d/mongodb.repo
echo "name=MongoDB Repository" >> /etc/yum.repos.d/mongodb.repo
echo "baseurl=https://repo.mongodb.org/yum/redhat/8/mongodb-org/4.2/x86_64/" >> /etc/yum.repos.d/mongodb.repo
echo "gpgcheck=1" >> /etc/yum.repos.d/mongodb.repo
echo "enabled=1" >> /etc/yum.repos.d/mongodb.repo
echo "gpgkey=https://www.mongodb.org/static/pgp/server-4.2.asc" >> /etc/yum.repos.d/mongodb.repo


# add fact-user to docker group
if [ ! "$(getent group docker)" ]
then
    sudo groupadd docker
fi
sudo usermod -aG docker "$FACTUSER"

if [ "$(pip3 freeze | grep enum34)" ]
then
        echo "Please uninstall the enum34 pypi package before continuing as it is not compatible with python >3.6 anymore"
        exit 1
fi

sudo -EH pip3 install --upgrade pip
sudo -EH pip3 install --upgrade virtualenv

echo "Installing Python Libraries for python based installation"
sudo -EH pip3 install --upgrade distro
sudo -EH pip3 install --upgrade python-magic

sudo -EH pip3 install --upgrade git+https://github.com/fkie-cad/common_helper_files.git
sudo -EH pip3 install --upgrade git+https://github.com/fkie-cad/common_helper_process.git

echo -e "Pre-Install-Routine complete! \\033[31mPlease reboot before running install.py\\033[0m"

exit 0
