#!/usr/bin/env python3

import logging
import pathlib

try:
    from helperFunctions.install import run_cmd_with_logging, check_distribution

    from ...installer import AbstractPluginInstaller
except ImportError:
    import sys
    print(
        'Could not import dependencies.\n' +
        'Try starting with "python3 -m plugins.analysis.PLUGIN_NAME.install" from the FACT_core/src directory',
        file=sys.stderr
    )
    sys.exit(1)

# The base directory of the plugin
base_path = pathlib.Path(__file__).resolve().parent


class LinterInstaller(AbstractPluginInstaller):
    def install_other_packages(self):
        run_cmd_with_logging('sudo luarocks install argparse', shell=True)
        run_cmd_with_logging('sudo luarocks install luacheck', shell=True)
        run_cmd_with_logging('sudo luarocks install luafilesystem', shell=True)

        run_cmd_with_logging('sudo npm install -g jshint', shell=True)

    def install_docker_images(self):
        run_cmd_with_logging('docker pull crazymax/linguist', shell=True)


# Alias for generic use
Installer = LinterInstaller

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(base_path, distribution)
    installer.install()
