#!/usr/bin/env python3  # noqa: EXE001

import logging
import urllib.request
from pathlib import Path

try:
    from fact.helperFunctions.install import OperateInDirectory, check_distribution, is_virtualenv, run_cmd_with_logging
    from fact.plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys

    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from fact.helperFunctions.install import OperateInDirectory, check_distribution, is_virtualenv, run_cmd_with_logging
    from fact.plugins.installer import AbstractPluginInstaller


BINWALK_VERSION = '2.4.1'


class BinwalkInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def build(self):
        url_binwalk = f'https://github.com/OSPG/binwalk/archive/refs/tags/v{BINWALK_VERSION}.tar.gz'
        dest_binwalk = f'binwalk-v{BINWALK_VERSION}.tar.gz'
        urllib.request.urlretrieve(url_binwalk, dest_binwalk)

        run_cmd_with_logging(f'tar -xf {dest_binwalk}')

        with OperateInDirectory(f'binwalk-{BINWALK_VERSION}'):
            if is_virtualenv():
                run_cmd_with_logging('pip install -U .')
            else:
                run_cmd_with_logging('sudo -EH pip3 install -U .')


# Alias for generic use
Installer = BinwalkInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(distribution)
    installer.install()
