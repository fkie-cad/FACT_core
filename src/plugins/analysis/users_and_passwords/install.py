#!/usr/bin/env python3

import logging
import os
import shutil
import subprocess
import urllib.request
from pathlib import Path
from subprocess import PIPE

try:
    from helperFunctions.install import check_distribution, run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys
    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from helperFunctions.install import check_distribution, run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller


class UsersAndPasswordsInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_system_packages(self):
        super().install_system_packages()

        lshw_p = subprocess.run('lshw -c display'.split(), stdout=PIPE, stderr=PIPE, check=True)
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

        Path('john').mkdir(exist_ok=True)
        run_cmd_with_logging(f'tar -xf {dest_john} -C john --strip-components 1')

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
        # FIXME This should be imported rather then executed
        run_cmd_with_logging(f'python3 {self.base_path}/internal/update_password_list.py')


# Alias for generic use
Installer = UsersAndPasswordsInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(distribution)
    installer.install()
