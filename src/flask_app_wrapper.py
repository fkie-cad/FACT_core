#! /usr/bin/env python3

import sys
import os
import pickle
import configparser
import logging

from web_interface.frontend_main import WebFrontEnd
from common_helper_files import get_directory_for_filename, get_version_string_from_git, create_dir_for_file


def _get_console_output_level(debug_flag):
    if debug_flag:
        return logging.DEBUG
    else:
        return logging.INFO


def _setup_logging(config, debug_flag=False):
    log_level = getattr(logging, config['Logging']['logLevel'], None)
    log_format = logging.Formatter(fmt="[%(asctime)s][%(module)s][%(levelname)s]: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG)
    create_dir_for_file(config['Logging']['logFile'])
    file_log = logging.FileHandler(config['Logging']['logFile'])
    file_log.setLevel(log_level)
    file_log.setFormatter(log_format)
    console_log = logging.StreamHandler()
    console_log.setLevel(_get_console_output_level(debug_flag))
    console_log.setFormatter(log_format)
    logger.addHandler(file_log)
    logger.addHandler(console_log)


def _load_config(args):
    config = configparser.ConfigParser()
    config.read(args.config_file)
    if args.log_file is not None:
        config['Logging']['logFile'] = args.log_file
    if args.log_level is not None:
        config['Logging']['logLevel'] = args.log_level
    return config


def shutdown(*_):
    web_interface.shutdown()


PROGRAM_VERSION = get_version_string_from_git(get_directory_for_filename(__file__))

args_path = sys.argv[-1]
if os.path.isfile(args_path):
    with open(args_path, "br") as fp:
        args = pickle.loads(fp.read())
    config = _load_config(args)
    _setup_logging(config, args.debug)
    web_interface = WebFrontEnd(config=config, program_version=PROGRAM_VERSION)
else:
    web_interface = WebFrontEnd(program_version=PROGRAM_VERSION)

app = web_interface.app
