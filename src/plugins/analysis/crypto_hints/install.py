#!/usr/bin/env python3

import pathlib
import urllib.request

from ...installer import AbstractPluginInstaller

# The base directory of the plugin
base_path = pathlib.Path(__file__).resolve().parent


class SoftwareComponentsInstaller(AbstractPluginInstaller):
    def install_files(self):
        url_crypto_signatures = 'https://raw.githubusercontent.com/Yara-Rules/rules/master/crypto/crypto_signatures.yar'
        dest_crypto_signatures = f'{self.base_path}/signatures/crypto_signatures.yar'
        pathlib.Path('signatures').mkdir(exist_ok=True)
        urllib.request.urlretrieve(url_crypto_signatures,
                                   dest_crypto_signatures)


# Alias for generic use
Installer = SoftwareComponentsInstaller
