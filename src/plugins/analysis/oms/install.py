#!/usr/bin/env python3

import pathlib

from helperFunctions.install import run_cmd_with_logging

from ...installer import AbstractPluginInstaller

# The base directory of the plugin
base_path = pathlib.Path(__file__).resolve().parent


class OmsInstaller(AbstractPluginInstaller):
    def do_last(self):
        # We dont care about the return value here
        # TODO why?
        run_cmd_with_logging('sudo -E freshclam', raise_error=False, shell=True)


# Alias for generic use
Installer = OmsInstaller
