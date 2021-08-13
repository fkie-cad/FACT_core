#!/usr/bin/env python3

import pathlib

from helperFunctions.install import run_cmd_with_logging

from ...installer import AbstractPluginInstaller

# The base directory of the plugin
base_path = pathlib.Path(__file__).resolve().parent


class FileSystemMetadataInstaller(AbstractPluginInstaller):
    def install_docker_images(self):
        run_cmd_with_logging('docker build -t fs_metadata_mounting docker', shell=True)


# Alias for generic use
Installer = FileSystemMetadataInstaller
