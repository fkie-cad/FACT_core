#!/usr/bin/env python3

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


class InputVectorsInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_docker_images(self):
        run_cmd_with_logging(f'docker build -t input-vectors {self.base_path}')
        run_cmd_with_logging('docker pull fkiecad/radare-web-gui:latest')


# Alias for generic use
Installer = InputVectorsInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(distribution)
    installer.install()
