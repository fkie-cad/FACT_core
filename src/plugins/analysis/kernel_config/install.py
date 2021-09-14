#!/usr/bin/env python3

import logging
import pathlib

try:
    from helperFunctions.install import check_distribution
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys
    SRC_PATH = pathlib.Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from helperFunctions.install import check_distribution
    from plugins.installer import AbstractPluginInstaller

# The base directory of the plugin
base_path = pathlib.Path(__file__).resolve().parent


class KernelConfigInstaller(AbstractPluginInstaller):
    pass


# Alias for generic use
Installer = KernelConfigInstaller

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(base_path, distribution)
    installer.install()
