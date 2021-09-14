#!/usr/bin/env python3

import logging
import os
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

# The base directory of the plugin
base_path = pathlib.Path(__file__).resolve().parent


class CveLookupInstaller(AbstractPluginInstaller):
    def install_files(self):
        # FIXME expose a function in setup_repository to to this directily
        # from python instead of executing the script
        os.chdir('internal')
        if not os.access('cve_cpe.db', os.R_OK):
            run_cmd_with_logging('python3 setup_repository.py')

        run_cmd_with_logging('python3 setup_repository.py --update')

        os.chdir(self.base_path)


# Alias for generic use
Installer = CveLookupInstaller

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(base_path, distribution)
    installer.install()
