#!/usr/bin/env python3

import logging
from pathlib import Path

try:
    from helperFunctions.install import run_cmd_with_logging
    from plugins.analysis.cwe_checker.internal.docker import DOCKER_IMAGE
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys

    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from helperFunctions.install import run_cmd_with_logging
    from plugins.analysis.cwe_checker.internal.docker import DOCKER_IMAGE
    from plugins.installer import AbstractPluginInstaller


class CweCheckerInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_docker_images(self) -> None:
        run_cmd_with_logging(f'docker pull {DOCKER_IMAGE}')


# Alias for generic use
Installer = CweCheckerInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    Installer().install()
