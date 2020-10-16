#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )" || exit 1

echo "------------------------------------"
echo "     install password cracker       "
echo "------------------------------------"

sudo -EH pip3 install --upgrade git+https://github.com/fkie-cad/common_helper_passwords.git || exit 1

mkdir -p bin/john/
if [ "$1" = "fedora" ]
then
  (
    # installing  prerequisite applications
    sudo dnf -y update
    sudo dnf -y install git make gcc openssl-devel
    sudo dnf -y install yasm gmp-devel libpcap-devel bzip2-devel
  ) || exit 1
else
  (
    # installing  prerequisite applications
    sudo apt-get -y install cmake bison flex libicu-dev
    sudo apt-get -y install build-essential libssl-dev git zlib1g-dev
    sudo apt-get -y install yasm libgmp-dev libpcap-dev pkg-config libbz2-dev

    OPENCL=$(sudo lshw -c display)
    if [[ ${OPENCL} == *"NVIDIA"* ]]; then
      sudo apt-get -y install nvidia-opencl-dev
    elif [[ ${OPENCL} == *"AMD"* ]]; then
      sudo apt-get -y install ocl-icd-opencl-dev opencl-headers
    fi
    ) || exit 1
fi

(
  cd bin/john
    # cloning JohnTheRipper from git repository
    wget -nc https://github.com/openwall/john/archive/1.9.0-Jumbo-1.tar.gz
    tar xf 1.9.0-Jumbo-1.tar.gz --strip-components 1
    rm 1.9.0-Jumbo-1.tar.gz

    # building JohnTheRipper
    cd src/
    sudo ./configure -disable-openmp && make -s clean && make -sj4
) || exit 1

# Add common credentials
(
	cd internal
	(
		cd passwords
		wget -N https://raw.githubusercontent.com/danielmiessler/SecLists/f9c1ec678c1cae461f1dc8b654ceb6719fd03d33/Passwords/Common-Credentials/10k-most-common.txt
	)
	python3 update_password_list.py
) || exit 1

exit 0
