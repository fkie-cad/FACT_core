#!/usr/bin/env bash

FACTUSER=$(whoami)

echo "Install Pre-Install Requirements"
sudo apt install python3-pip git

echo "Installing Docker"
sudo apt-get -y remove docker docker-engine docker.io
sudo apt-get -y install apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get update
sudo apt-get -y install docker-ce
sudo systemctl enable docker
sudo usermod -aG docker $FACTUSER

echo "Pre-Install-Routine complete! Please reboot before running install.py"
