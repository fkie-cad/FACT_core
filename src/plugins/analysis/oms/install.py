#!/usr/bin/env python3

import logging
from pathlib import Path

try:
    from helperFunctions.install import check_distribution, run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys
    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from helperFunctions.install import check_distribution, run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller


class OmsInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def do_last(self):
        # We don't care about the return value here, e.g. on Ubunut clamav-freshclam.service already runs freshclam,
        # this will cause another invocation of freshclam to fail.
        # FIXME Are there other reasons?
        run_cmd_with_logging('sudo -E freshclam', raise_error=False)


# Alias for generic use
Installer = OmsInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(distribution)
    installer.install()
