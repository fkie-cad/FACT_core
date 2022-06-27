#!/usr/bin/env python3
# pylint: disable=ungrouped-imports

import logging
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


JOHN_POT = Path(__file__).parent / 'bin' / 'john.pot'


class UsersAndPasswordsInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_docker_images(self):
        run_cmd_with_logging(f'docker build -t fact/john:alpine-3.14 {self.base_path}/docker')

    def install_files(self):
        if not JOHN_POT.is_file():
            JOHN_POT.parent.mkdir(exist_ok=True)
            JOHN_POT.touch()


# Alias for generic use
Installer = UsersAndPasswordsInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    installer = Installer(check_distribution())
    installer.install()
