#!/usr/bin/env python3

import pathlib

from helperFunctions.install import run_cmd_with_logging

from ...installer import AbstractPluginInstaller

# The base directory of the plugin
base_path = pathlib.Path(__file__).resolve().parent


class CweCheckerInstaller(AbstractPluginInstaller):
    def install_docker_images(self):
        run_cmd_with_logging('docker pull fkiecad/cwe_checker:latest', shell=True)


# Alias for generic use
Installer = CweCheckerInstaller
