#!/usr/bin/env python3

import logging
import urllib.request
from pathlib import Path

try:
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys

    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from plugins.installer import AbstractPluginInstaller


class SoftwareComponentsInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_files(self):
        url_crypto_signatures = 'https://raw.githubusercontent.com/Yara-Rules/rules/master/crypto/crypto_signatures.yar'
        dest_crypto_signatures = f'{self.base_path}/signatures/crypto_signatures.yar'
        Path('signatures').mkdir(exist_ok=True)
        urllib.request.urlretrieve(url_crypto_signatures, dest_crypto_signatures)


# Alias for generic use
Installer = SoftwareComponentsInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    Installer().install()
