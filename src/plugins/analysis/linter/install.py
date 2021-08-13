#!/usr/bin/env python3

import pathlib

from helperFunctions.install import run_cmd_with_logging

from ...installer import AbstractPluginInstaller

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
