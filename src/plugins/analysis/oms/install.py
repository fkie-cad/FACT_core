#!/usr/bin/env python3

import logging
import pathlib

try:
    from helperFunctions.install import check_distribution, run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys
    SRC_PATH = pathlib.Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from helperFunctions.install import check_distribution, run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller


class OmsInstaller(AbstractPluginInstaller):
    # The base directory of the plugin
    base_path = pathlib.Path(__file__).resolve().parent

    def do_last(self):
        # We dont care about the return value here
        # TODO why?
        run_cmd_with_logging('sudo -E freshclam', raise_error=False)


# Alias for generic use
Installer = OmsInstaller

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(distribution)
    installer.install()
