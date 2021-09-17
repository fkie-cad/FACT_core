#!/usr/bin/env python3

import logging
from pathlib import Path

from .internal.extract_os_names import extract_names

try:
    from helperFunctions.install import check_distribution, run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys
    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from helperFunctions.install import check_distribution, run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller


class SoftwareComponentsInstaller(AbstractPluginInstaller):
    # The base directory of the plugin
    base_path = Path(__file__).resolve().parent

    def install_docker_images(self):
        run_cmd_with_logging('docker build -t fact/format_string_resolver docker')

    def install_files(self):
        extract_names()


# Alias for generic use
Installer = SoftwareComponentsInstaller

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(distribution)
    installer.install()
