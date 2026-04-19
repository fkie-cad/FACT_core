#!/usr/bin/env python3
"""Installer for the ghidra_analysis plugin.

This installer builds a local Docker image that bundles Ghidra and a JDK so
that the plugin can run Ghidra in headless mode without requiring a host
installation.  The Dockerfile lives in the ``docker/`` sub-directory next to
this script.
"""

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


class GhidraAnalysisInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_docker_images(self):
        self._build_docker_image('ghidra-fact:latest', dockerfile_path=self.base_path / 'docker')


# Alias for generic use
Installer = GhidraAnalysisInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    Installer().install()
