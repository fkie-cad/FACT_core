#!/usr/bin/env python3
# pylint: disable=duplicate-code,ungrouped-imports

import logging
from pathlib import Path

try:
    from plugins.analysis.software_components.internal.extract_os_names import extract_names
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys

    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from plugins.analysis.software_components.internal.extract_os_names import extract_names
    from plugins.installer import AbstractPluginInstaller


class SoftwareComponentsInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_docker_images(self):
        self._build_docker_image('fact/format_string_resolver')

    def install_files(self):
        extract_names()


# Alias for generic use
Installer = SoftwareComponentsInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    Installer().install()
