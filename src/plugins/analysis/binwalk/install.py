#!/usr/bin/env python3

import logging
import urllib.request
from pathlib import Path

try:
    from helperFunctions.install import OperateInDirectory, check_distribution, is_virtualenv, run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys
    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from helperFunctions.install import OperateInDirectory, check_distribution, is_virtualenv, run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller


class BinwalkInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def build(self):
        # We need a version >=2.3.0 because of 1534001b96b8d543dcbb52845526326b61119f8c
        # Ubuntu 20.04 is currently on 2.2.0
        url_binwalk = 'https://github.com/ReFirmLabs/binwalk/archive/refs/tags/v2.3.1.tar.gz'
        dest_binwalk = 'binwalk-v2.3.1.tar.gz'
        urllib.request.urlretrieve(url_binwalk, dest_binwalk)

        run_cmd_with_logging(f'tar -xf {dest_binwalk}')

        with OperateInDirectory('binwalk-2.3.1'):
            run_cmd_with_logging('python3 setup.py build')
            if is_virtualenv():
                run_cmd_with_logging('python3 setup.py install')
            else:
                run_cmd_with_logging('sudo python3 setup.py install')


# Alias for generic use
Installer = BinwalkInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(distribution)
    installer.install()
