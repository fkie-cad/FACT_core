#! /usr/bin/env python3
"""
Firmware Analysis and Comparison Tool (FACT)
Copyright (C) 2015-2026  Fraunhofer FKIE

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging
import sys
from pathlib import Path

from helperFunctions.fileSystem import get_src_dir
from helperFunctions.yara import compile_plugin_yara_signatures

SIGNATURE_DIR = Path(get_src_dir()) / 'analysis/signatures'
PLUGIN_DIR = Path(get_src_dir()) / 'plugins/analysis'


def main() -> int:
    for plugin_dir in PLUGIN_DIR.iterdir():
        if not plugin_dir.is_dir():
            continue
        signature_dir = plugin_dir / 'signatures'
        if signature_dir.is_dir():
            logging.info(f'Compiling signatures in {signature_dir}')
            compile_plugin_yara_signatures(signature_dir, SIGNATURE_DIR)

    return 0


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
