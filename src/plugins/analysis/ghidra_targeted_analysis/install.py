#!/usr/bin/env python3
"""Installer for the ghidra_targeted_analysis plugin.

This plugin shares the Docker image with :mod:`ghidra_analysis`.  Both
images are named ``ghidra-fact:latest`` and built from the same Dockerfile
located in ``src/plugins/analysis/ghidra_analysis/docker/``.

If you have already installed ``ghidra_analysis``, the Docker image is
already present and this installer is a no-op for the Docker step.
"""

import logging
from pathlib import Path

try:
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys

    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from plugins.installer import AbstractPluginInstaller

# The Dockerfile lives in the sibling ghidra_analysis plugin directory
_GHIDRA_ANALYSIS_DOCKER = (
    Path(__file__).resolve().parent.parent / 'ghidra_analysis' / 'docker'
)


class GhidraTargetedAnalysisInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_docker_images(self):
        self._build_docker_image('ghidra-fact:latest', dockerfile_path=_GHIDRA_ANALYSIS_DOCKER)


# Alias for generic use
Installer = GhidraTargetedAnalysisInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    Installer().install()
