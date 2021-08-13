#!/usr/bin/env python3

import pathlib

from helperFunctions.install import run_cmd_with_logging

from ...installer import AbstractPluginInstaller

# The base directory of the plugin
base_path = pathlib.Path(__file__).resolve().parent


class SoftwareComponentsInstaller(AbstractPluginInstaller):
    def install_docker_images(self):
        run_cmd_with_logging('docker build -t fact/format_string_resolver docker', shell=True)

    def install_files(self):
        # pylint:disable=import-outside-toplevel
        from .internal.extract_os_names import extract_names
        extract_names()


# Alias for generic use
Installer = SoftwareComponentsInstaller
