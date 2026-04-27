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

import yara

from helperFunctions.fileSystem import get_src_dir

SIGNATURE_DIR = Path(get_src_dir()) / 'analysis/signatures'
PLUGIN_DIR = Path(get_src_dir()) / 'plugins/analysis'


def _create_joint_signature_file(directory: Path) -> str:
    all_signatures = []
    for signature_file in directory.iterdir():
        all_signatures.append(signature_file.read_text())
    return '\n'.join(all_signatures)


def _get_plugin_name(plugin_signature_dir: Path) -> str:
    return plugin_signature_dir.parent.name


def _save_compiled_signatures(directory: Path, rules: str) -> None:
    target_path = SIGNATURE_DIR / f'{_get_plugin_name(directory)}.yc'
    try:
        rules: yara.Rules = yara.compile(source=rules, externals={'test_flag': 'false'})
        rules.save(str(target_path.absolute()))
    except SyntaxError as error:
        logging.exception(f'[ERROR] Creation of {target_path.name} failed: {error}')


def _create_signature_dir() -> None:
    logging.debug(f'Creating signature directory {SIGNATURE_DIR}')
    SIGNATURE_DIR.mkdir(parents=True, exist_ok=True)


def main() -> int:
    _create_signature_dir()
    for plugin_dir in PLUGIN_DIR.iterdir():
        if not plugin_dir.is_dir():
            continue
        signature_dir = plugin_dir / 'signatures'
        if signature_dir.is_dir():
            logging.info(f'Compiling signatures in {signature_dir}')
            rules = _create_joint_signature_file(signature_dir)
            _save_compiled_signatures(signature_dir, rules)

    return 0


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    sys.exit(main())
