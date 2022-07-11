#! /usr/bin/env python3
'''
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2022  Fraunhofer FKIE

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
import pickle
import sys
from pathlib import Path

from helperFunctions.program_setup import setup_logging
from web_interface.frontend_main import WebFrontEnd


def _get_console_output_level(debug_flag):
    if debug_flag:
        return logging.DEBUG
    return logging.INFO


def _load_config(args):
    config = configparser.ConfigParser()
    config.read(args.config_file)
    if args.log_file is not None:
        config['logging']['logfile'] = args.log_file
    if args.log_level is not None:
        config['logging']['loglevel'] = args.log_level
    return config


def create_web_interface():
    args_path = Path(sys.argv[-1])
    if args_path.is_file():
        args = pickle.loads(args_path.read_bytes())
        config = _load_config(args)
        setup_logging(config, args, component='frontend')
        return WebFrontEnd(config=config)
    return WebFrontEnd()


web_interface = create_web_interface()
app = web_interface.app
