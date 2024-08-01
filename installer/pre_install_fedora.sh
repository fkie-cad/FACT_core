#!/usr/bin/env bash

# cd in this files directory for relative paths to work
cd "$( dirname "${BASH_SOURCE[0]}" )"

FACTUSER=$(whoami)

echo "Install Pre-Install Requirements"

sudo dnf install -y python3-pip git libffi-devel ca-certificates grubby curl

echo "Installing Docker"

curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
rm get-docker.sh

sudo grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=0"
sudo systemctl start docker
sudo systemctl enable docker

echo "Adding mongodb repo"
sudo touch /etc/yum.repos.d/mongodb.repo
echo "[mongodb-org-3.6]" | sudo tee -a /etc/yum.repos.d/mongodb.repo
echo "name=MongoDB Repository" | sudo tee -a /etc/yum.repos.d/mongodb.repo
echo "baseurl=https://repo.mongodb.org/yum/redhat/7/mongodb-org/3.6/x86_64/" | sudo tee -a /etc/yum.repos.d/mongodb.repo
echo "gpgcheck=1" | sudo tee -a /etc/yum.repos.d/mongodb.repo
echo "enabled=1" | sudo tee -a /etc/yum.repos.d/mongodb.repo
echo "gpgkey=https://www.mongodb.org/static/pgp/server-3.6.asc" | sudo tee -a /etc/yum.repos.d/mongodb.repo


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


echo "Installing Python Libraries for python based installation"
sudo -EH pip install -r ./requirements_pre_install.txt


echo -e "Pre-Install-Routine complete! \\033[31mPlease reboot before running install.py\\033[0m"

exit 0
