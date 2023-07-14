#!/usr/bin/env python3  # noqa: EXE001

import logging
from pathlib import Path

try:
    from helperFunctions.install import check_distribution
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys

    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from helperFunctions.install import check_distribution
    from plugins.installer import AbstractPluginInstaller


class DeviceTreeInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent


# Alias for generic use
Installer = DeviceTreeInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(distribution)
    installer.install()
