#!/usr/bin/env python3

import os
import pathlib

from helperFunctions.install import run_cmd_with_logging

from ...installer import AbstractPluginInstaller

# The base directory of the plugin
base_path = pathlib.Path(__file__).resolve().parent


class CveLookupInstaller(AbstractPluginInstaller):
    def install_files(self):
        # TODO expose a function in setup_repository to to this directily
        # from python instead of executing the script
        os.chdir('internal')
        if not os.access('cve_cpe.db', os.R_OK):
            run_cmd_with_logging('python3 setup_repository.py')

        run_cmd_with_logging('python3 setup_repository.py --update')

        os.chdir(self.base_path)


# Alias for generic use
Installer = CveLookupInstaller
