#!/usr/bin/env python3

import logging
import urllib.request
from pathlib import Path

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

    def install_docker_images(self):
        run_cmd_with_logging(f'docker build {self._get_docker_build_args()} -t fact/john:alpine-3.14 {self.base_path}/docker')

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
