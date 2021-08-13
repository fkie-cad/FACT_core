#!/usr/bin/env python3

import pathlib
import urllib.request

from helperFunctions.install import OperateInDirectory, run_cmd_with_logging

from ...installer import AbstractPluginInstaller

# The base directory of the plugin
base_path = pathlib.Path(__file__).resolve().parent


class BinwalkInstaller(AbstractPluginInstaller):
    def build(self):
        # We need a version >=2.3.0 because of 1534001b96b8d543dcbb52845526326b61119f8c
        # Ubuntu 20.04 is currently on 2.2.0
        url_binwalk = 'https://github.com/ReFirmLabs/binwalk/archive/refs/tags/v2.3.1.tar.gz'
        dest_binwalk = 'binwalk-v2.3.1.tar.gz'
        urllib.request.urlretrieve(url_binwalk, dest_binwalk)

        run_cmd_with_logging(f'tar -xf {dest_binwalk}', shell=True)

        with OperateInDirectory('binwalk-2.3.1'):
            run_cmd_with_logging('python3 setup.py build', shell=True)
            run_cmd_with_logging('sudo python3 setup.py install', shell=True)


# Alias for generic use
Installer = BinwalkInstaller
