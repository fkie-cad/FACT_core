#!/usr/bin/env python3
# pylint: disable=ungrouped-imports

import logging
from pathlib import Path

try:
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys
    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from plugins.installer import AbstractPluginInstaller


class KnownVulnerabilitiesInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_docker_images(self):
        self._build_docker_image('fact/known-vulnerabilities')


# Alias for generic use
Installer = KnownVulnerabilitiesInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    Installer().install()
