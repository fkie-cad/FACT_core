#!/usr/bin/env python3

import logging
import pathlib

try:
    from helperFunctions.install import check_distribution, run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys
    SRC_PATH = pathlib.Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from helperFunctions.install import check_distribution, run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller

# The base directory of the plugin
base_path = pathlib.Path(__file__).resolve().parent


class FileSystemMetadataInstaller(AbstractPluginInstaller):
    def install_docker_images(self):
        run_cmd_with_logging('docker build -t fs_metadata_mounting docker')


# Alias for generic use
Installer = FileSystemMetadataInstaller

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(base_path, distribution)
    installer.install()
