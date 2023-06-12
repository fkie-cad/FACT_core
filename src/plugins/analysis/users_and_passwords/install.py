#!/usr/bin/env python3
# pylint: disable=duplicate-code,ungrouped-imports

import logging
from pathlib import Path

try:
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys

    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from plugins.installer import AbstractPluginInstaller

JOHN_POT = Path(__file__).parent / 'bin' / 'john.pot'


class UsersAndPasswordsInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_docker_images(self):
        self._build_docker_image('fact/john:alpine-3.18')

    def install_files(self):
        if not JOHN_POT.is_file():
            JOHN_POT.parent.mkdir(exist_ok=True)
            JOHN_POT.touch()


# Alias for generic use
Installer = UsersAndPasswordsInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    Installer().install()
