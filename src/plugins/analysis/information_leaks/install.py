#!/usr/bin/env python3

import logging
import platform
from pathlib import Path

try:
    from helperFunctions.install import install_github_release
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys

    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from helperFunctions.install import install_github_release
    from plugins.installer import AbstractPluginInstaller

ARCH_TO_PAKET_ARCH = {
    'x86_64': 'x64',
    'aarch64': 'arm64',
}
BIN_DIR = Path(__file__).absolute().parent / 'bin'


class InformationLeaksInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_files(self) -> None:
        BIN_DIR.mkdir(exist_ok=True)
        version = '8.30.1'
        arch = ARCH_TO_PAKET_ARCH[platform.machine()]
        install_github_release(
            target_path=BIN_DIR,
            project_path='gitleaks/gitleaks',
            file=f'gitleaks_{version}_linux_{arch}.tar.gz',
            version=f'v{version}',
            file_list=['gitleaks'],
        )


# Alias for generic use
Installer = InformationLeaksInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    Installer().install()
