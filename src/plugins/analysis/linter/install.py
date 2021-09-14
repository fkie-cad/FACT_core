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


class LinterInstaller(AbstractPluginInstaller):
    def install_other_packages(self):
        run_cmd_with_logging('sudo luarocks install argparse')
        run_cmd_with_logging('sudo luarocks install luacheck')
        run_cmd_with_logging('sudo luarocks install luafilesystem')

        run_cmd_with_logging('sudo npm install -g jshint')

    def install_docker_images(self):
        run_cmd_with_logging('docker pull crazymax/linguist')


# Alias for generic use
Installer = LinterInstaller

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(base_path, distribution)
    installer.install()
