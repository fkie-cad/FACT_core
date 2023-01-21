# Install FACT using vagrant

## Setting up
```sh
# 1. install vagrant and virtualbox
sudo apt install virtualbox vagrant

# 2. reboot your machine to ensure that the virtualbox dkms is loaded into the kernel
sudo reboot now

# 3. create a new folder for vagrant
mkdir FACT-master
cd FACT-master

# 4. create a FACT-master configuration
vagrant init fact-cad/FACT-master

# 5. edit the Vagrantfile to your needs! an example can be found below.
nano Vagrantfile

# 6. start the VM. The first time executing this command will take some time, as the box is getting downloaded and imported. So better grab a coffee!
vagrant up

# Bonus: if you want to ssh into the vm, execute:
vagrant ssh

# Bonus: if you want to stop the vm, execute:
vagrant halt
```

## Upgrading your Box

Congrats, FACT is now available [here](http://localhost:5000) (`http://localhost:5000`)!

An exemplary Vagrantfile config may look like this:

```ruby
# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "fact-cad/FACT-master"  # base image
  config.vm.network "forwarded_port", guest: 5000, host: 5000  # listen port for FACT

  config.vm.provider "virtualbox" do |vb|
    vb.gui = false  # suppress the virtualbox gui popping up on machine start
    vb.cpus = 4  # assign 4 CPU cores to the VM
    vb.memory = 6144 # assign 6GB RAM to the VM
  end
end
```
Note: There is currently no automated process to migrate analysis data between boxes. Until we established export/import functionality, please do not update your Vagrant box if you want to keep your analysis results!
