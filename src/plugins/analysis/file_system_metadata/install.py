#!/usr/bin/env python3

import logging
from pathlib import Path

try:
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys

    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from plugins.installer import AbstractPluginInstaller


class FileSystemMetadataInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_docker_images(self):
        self._build_docker_image('fact/fs_metadata:latest')


# Alias for generic use
Installer = FileSystemMetadataInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    Installer().install()
