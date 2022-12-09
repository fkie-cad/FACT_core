#!/usr/bin/env python3

import logging
from pathlib import Path

try:
    from helperFunctions.install import run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys

    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from helperFunctions.install import run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller


class IpcAnalyzerInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_docker_images(self):
        run_cmd_with_logging("docker build -t ipc ./docker")


# Alias for generic use
Installer = IpcAnalyzerInstaller

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    Installer().install()
