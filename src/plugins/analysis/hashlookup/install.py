#!/usr/bin/env python3
import argparse
import logging
from pathlib import Path

import requests

try:
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys

    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from plugins.installer import AbstractPluginInstaller

BLOOM_FILTER_URL = 'https://cra.circl.lu/hashlookup/hashlookup-full.bloom'


class HashLookupInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def __init__(self, *args, cli_args: argparse.Namespace | None = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.cli_args = cli_args

    def install_files(self) -> None:
        """
        Install files for the hashlookup plugin.
        """
        if self.cli_args is None or not self.cli_args.local:
            return
        bin_dir = Path(__file__).parent / 'bin'
        bin_dir.mkdir(parents=True, exist_ok=True)
        output = bin_dir / 'hashlookup-full.bloom'
        with output.open('wb') as fp, requests.get(BLOOM_FILTER_URL, stream=True) as response:  # noqa: S113
            response.raise_for_status()
            for chunk in response.iter_content(chunk_size=8192):
                fp.write(chunk)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('-l', '--local', action='store_true')
    return parser.parse_args()


# Alias for generic use
Installer = HashLookupInstaller

if __name__ == '__main__':
    args = _parse_args()
    logging.basicConfig(level=logging.INFO if not args.debug else logging.DEBUG)
    Installer().install()
