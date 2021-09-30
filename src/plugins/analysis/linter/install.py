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


class LinterInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_other_packages(self):
        run_cmd_with_logging('sudo luarocks install argparse')
        run_cmd_with_logging('sudo luarocks install luacheck')
        run_cmd_with_logging('sudo luarocks install luafilesystem')

        # FIXME: deactivated because of npm installation issues
        # run_cmd_with_logging('sudo npm install -g jshint')

    def install_docker_images(self):
        run_cmd_with_logging('docker pull crazymax/linguist')


# Alias for generic use
Installer = LinterInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(distribution)
    installer.install()
