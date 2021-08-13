#!/usr/bin/env python3

import logging
import pathlib
import urllib.request

try:
    from helperFunctions.install import check_distribution
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


class SoftwareComponentsInstaller(AbstractPluginInstaller):
    def install_files(self):
        url_crypto_signatures = 'https://raw.githubusercontent.com/Yara-Rules/rules/master/crypto/crypto_signatures.yar'
        dest_crypto_signatures = f'{self.base_path}/signatures/crypto_signatures.yar'
        pathlib.Path('signatures').mkdir(exist_ok=True)
        urllib.request.urlretrieve(url_crypto_signatures,
                                   dest_crypto_signatures)


# Alias for generic use
Installer = SoftwareComponentsInstaller

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(base_path, distribution)
    installer.install()
