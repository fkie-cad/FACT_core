#! /usr/bin/env python3
"""
This script updates the password list
"""

import argparse
import logging
import os
import sys

from common_helper_files import delete_file, get_dir_of_file, write_binary_to_file
from common_helper_passwords import get_merged_password_set

PROGRAM_NAME = 'FACT Password List Updater'
PROGRAM_VERSION = '0.3'
PROGRAM_DESCRIPTION = 'Initialize or update password list'

THIS_FILE_DIR = get_dir_of_file(__file__)


def _setup_argparser():
    parser = argparse.ArgumentParser(description=f'{PROGRAM_NAME} - {PROGRAM_DESCRIPTION}')
    parser.add_argument('-V', '--version', action='version', version=f'{PROGRAM_NAME} {PROGRAM_VERSION}')
    parser.add_argument('-d', '--debug', action='store_true', default=False, help='print debug messages')
    parser.add_argument(
        '-p', '--password_lists_directory', default=os.path.join(THIS_FILE_DIR, 'passwords')  # noqa: PTH118
    )
    parser.add_argument(
        '-o', '--output_file', default=os.path.join(THIS_FILE_DIR, '../../../..', 'bin/passwords.txt')  # noqa: PTH118
    )
    return parser.parse_args()


def _setup_logging(args):
    log_format = logging.Formatter(
        fmt='[%(asctime)s][%(module)s][%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )
    logger = logging.getLogger('')
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    console_logger = logging.StreamHandler()
    console_logger.setFormatter(log_format)
    logger.addHandler(console_logger)


def _write_password_file(password_set, file_path):
    content = '\n'.join(list(password_set)).encode('utf-8')
    write_binary_to_file(content, file_path)


if __name__ == '__main__':
    args = _setup_argparser()
    _setup_logging(args)

    logging.info('Update Password List...')

    logging.debug(f'remove old password file: {args.output_file}')
    delete_file(args.output_file)

    logging.debug(f'read password files in {args.password_lists_directory}')
    passwords = get_merged_password_set(args.password_lists_directory)

    logging.info(f'{len(passwords)} unique passwords found')

    logging.debug(f'writing passwords to file {args.output_file}')
    _write_password_file(passwords, args.output_file)

    sys.exit()
