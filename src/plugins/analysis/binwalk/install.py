#!/usr/bin/env python3

import logging
import pathlib
import urllib.request

try:
    from helperFunctions.install import OperateInDirectory, check_distribution, run_cmd_with_logging

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

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(base_path, distribution)
    installer.install()
