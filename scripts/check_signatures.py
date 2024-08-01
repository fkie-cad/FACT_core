#! /usr/bin/env python3
"""
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2024 Fraunhofer FKIE

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import argparse
import logging

from fact.helperFunctions.yara_signature_testing import SignatureTesting

PROGRAM_NAME = 'Component Signature Test Framework (CSTF)'
PROGRAM_VERSION = '0.2'
PROGRAM_DESCRIPTION = 'Check if each line in a file is matched by a yara rule.'


def _setup_argparser():
    parser = argparse.ArgumentParser(description=f'{PROGRAM_NAME} - {PROGRAM_DESCRIPTION}')
    parser.add_argument('-V', '--version', action='version', version=f'{PROGRAM_NAME} {PROGRAM_VERSION}')
    parser.add_argument('test_file', help='File containing the list of signatures')
    parser.add_argument(
        '--yara_path',
        help='File or Folder containing yara signatures (Extension .yara mandatory)',
        default='software_signatures/',
    )
    return parser.parse_args()


def _setup_logging():
    log_format = logging.Formatter(
        fmt='[%(asctime)s][%(module)s][%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )
    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG)
    console_log = logging.StreamHandler()
    console_log.setLevel(logging.INFO)
    console_log.setFormatter(log_format)
    logger.addHandler(console_log)


if __name__ == '__main__':
    args = _setup_argparser()
    _setup_logging()

    sig_tester = SignatureTesting()
    diff = sig_tester.check(args.yara_path, args.test_file)
    if diff:
        logging.error(f'Missing yara signatures for: {diff}')
    else:
        logging.info('Found all strings')
