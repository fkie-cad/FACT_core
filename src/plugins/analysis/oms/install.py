#!/usr/bin/env python3

import logging
import pathlib

try:
    from helperFunctions.install import check_distribution, run_cmd_with_logging

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


class OmsInstaller(AbstractPluginInstaller):
    def do_last(self):
        # We dont care about the return value here
        # TODO why?
        run_cmd_with_logging('sudo -E freshclam', raise_error=False)


# Alias for generic use
Installer = OmsInstaller

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(base_path, distribution)
    installer.install()
