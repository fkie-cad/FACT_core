#! /usr/bin/env python3
'''
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2018  Fraunhofer FKIE

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
'''

import configparser
import logging
import os
import pickle
import sys

from common_helper_files import create_dir_for_file

from web_interface.frontend_main import WebFrontEnd


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


args_path = sys.argv[-1]
if os.path.isfile(args_path):
    with open(args_path, "br") as fp:
        args = pickle.loads(fp.read())
    config = _load_config(args)
    _setup_logging(config, args.debug)
    web_interface = WebFrontEnd(config=config)
else:
    web_interface = WebFrontEnd()

app = web_interface.app
