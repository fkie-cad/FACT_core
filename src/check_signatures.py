#! /usr/bin/env python3
"""
This tool enables the comparison between a user created list of component signatures, e.g. saved as a file, with
a set of yara signatures.
If desired one can review the un-found components in the command line.
"""

import argparse
import logging

from helperFunctions.yara_signature_testing import SignatureTesting


PROGRAM_NAME = "Component Signature Test Framework (CSTF)"
PROGRAM_VERSION = "0.2"
PROGRAM_DESCRIPTION = "Check if each line in a file is matched by a yara rule."


def _setup_argparser():
    parser = argparse.ArgumentParser(description="{} - {}".format(PROGRAM_NAME, PROGRAM_DESCRIPTION))
    parser.add_argument('-V', '--version', action='version',
                        version="{} {}".format(PROGRAM_NAME, PROGRAM_VERSION))
    parser.add_argument("test_file", help="File containing the list of signatures")
    parser.add_argument("--yara_path", help="File or Folder containing yara signatures (Extension .yara mandatory)", default="software_signatures/")
    return parser.parse_args()


def _setup_logging():
    log_format = logging.Formatter(fmt="[%(asctime)s][%(module)s][%(levelname)s]: %(message)s",
                                   datefmt="%Y-%m-%d %H:%M:%S")
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
        logging.error("Missing yara signatures for: {}".format(diff))
    else:
        logging.info("Found all strings")
