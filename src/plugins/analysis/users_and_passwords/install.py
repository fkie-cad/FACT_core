#!/usr/bin/env python3

import os
import pathlib
import shutil
import subprocess
import urllib.request

from helperFunctions.install import run_cmd_with_logging

from ...installer import AbstractPluginInstaller

# The base directory of the plugin
base_path = pathlib.Path(__file__).resolve().parent


class UsersAndPasswordsInstaller(AbstractPluginInstaller):

    def install_system_packages(self):
        super().install_system_packages()

        lshw_p = subprocess.run('lshw -c display'.split(), capture_output=True, check=True)
        opencl_pkgs = []
        if lshw_p.stdout == 'NVIDIA':
            opencl_pkgs = ['nvidia-opencl-dev']
        elif lshw_p.stdout == 'AMD':
            opencl_pkgs = ['ocl-icd-opencl-dev', 'opencl-headers']

        # Somehow we don't care about opencl on fedora
        if self.distribution != 'fedora':
            run_cmd_with_logging('sudo apt install -y ' + ' '.join(opencl_pkgs))

    def build(self):
        url_john = 'https://github.com/openwall/john/archive/1.9.0-Jumbo-1.tar.gz'
        dest_john = '1.9.0-Jumbo-1.tar.gz'
        urllib.request.urlretrieve(url_john, dest_john)

        pathlib.Path('john').mkdir(exist_ok=True)
        run_cmd_with_logging(f'tar -xf {dest_john} -C john --strip-components 1', shell=True)

        os.chdir('john/src')
        run_cmd_with_logging('sudo ./configure -disable-openmp', shell=True)
        run_cmd_with_logging('make -s clean && make -sj$(nproc)', shell=True)

        os.chdir(self.build_path)
        # Ensure the directory is empty
        shutil.rmtree(f'{self.base_path}/bin', ignore_errors=True)
        shutil.move('john/run', f'{self.base_path}/bin')

    def install_files(self):
        url_10_k_most_common = 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt'
        dest_10_k_most_common = f'{self.base_path}/internal/passwords/10k-most-common.txt'
        urllib.request.urlretrieve(url_10_k_most_common, dest_10_k_most_common)


# Alias for generic use
Installer = UsersAndPasswordsInstaller
