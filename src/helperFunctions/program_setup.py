'''
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2019  Fraunhofer FKIE

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

import argparse
import logging
import sys
from pathlib import Path

from common_helper_files import create_dir_for_file

import config
from config import cfg
from helperFunctions.fileSystem import get_config_dir
from helperFunctions.logging import ColoringFormatter
from version import __VERSION__


def program_setup(name, description, component=None, version=__VERSION__, command_line_options=None):
    '''
    Creates an ArgumentParser with some default options and parse command_line_options.

    :param command_line_options: The arguments to parse
    :return: The parsed args from argparser
    '''
    args = _setup_argparser(name, description, command_line_options=command_line_options or sys.argv, version=version)
    config.load(args.config_file)
    set_logging_cfg_from_args(args)
    setup_logging(args, component)
    return args


def set_logging_cfg_from_args(args: argparse.Namespace):
    """Command line parameters will overwrite values from the config file"""
    if args.log_file is not None:
        cfg.logging.logfile = args.log_file
    if args.log_level is not None:
        cfg.logging.loglevel = args.log_level


def _setup_argparser(name, description, command_line_options, version=__VERSION__):
    '''
    Sets up an ArgumentParser with some default flags and parses
    command_line_options.

    :return: The populated namespace from ArgumentParser.parse_args
    '''

    parser = argparse.ArgumentParser(description=f'{name} - {description}')
    parser.add_argument('-V', '--version', action='version', version=f'{name} {version}')
    parser.add_argument('-l', '--log_file', help='path to log file', default=None)
    parser.add_argument(
        '-L', '--log_level', help='define the log level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default=None
    )
    parser.add_argument('-d', '--debug', action='store_true', default=False, help='print debug messages')
    parser.add_argument('-s', '--silent', action='store_true', default=False, help='don\'t log to command line')
    parser.add_argument('-C', '--config_file', help='set path to config File', default=f'{get_config_dir()}/main.cfg')
    parser.add_argument(
        '-t', '--testing', default=False, action='store_true', help='shutdown system after one iteration'
    )
    return parser.parse_args(command_line_options[1:])


def setup_logging(args, component=None):
    log_level = getattr(logging, cfg.logging.loglevel, None)
    log_format = dict(fmt='[%(asctime)s][%(module)s][%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG)

    log_file = get_log_file_for_component(component)
    create_dir_for_file(log_file)
    file_log = logging.FileHandler(log_file)
    file_log.setLevel(log_level)
    file_log.setFormatter(logging.Formatter(**log_format))
    logger.addHandler(file_log)

    if not args.silent:
        console_log = logging.StreamHandler()
        console_log.setLevel(logging.DEBUG if args.debug else logging.INFO)
        console_log.setFormatter(ColoringFormatter(**log_format))
        logger.addHandler(console_log)


def get_log_file_for_component(component: str) -> str:
    log_file = Path(cfg.logging.logfile)
    if component is None:
        return cfg.logging.logfile
    return f'{log_file.parent}/{log_file.stem}_{component}{log_file.suffix}'
