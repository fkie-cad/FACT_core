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
import configparser
import logging
import sys
from configparser import ConfigParser
from pathlib import Path

from common_helper_files import create_dir_for_file

from helperFunctions.config import get_config_dir
from helperFunctions.logging import ColoringFormatter
from version import __VERSION__


def program_setup(name, description, component=None, version=__VERSION__, command_line_options=None):
    '''
    Creates an ArgumentParser with some default options and parse command_line_options.

    :param command_line_options: The arguments to parse
    :return: A tuple (args, config) containing the parsed args from argparser and the config read
    '''
    args = _setup_argparser(name, description, command_line_options=command_line_options or sys.argv, version=version)
    config = _load_config(args)
    _setup_logging(config, args, component)
    return args, config


def _setup_argparser(name, description, command_line_options, version=__VERSION__):
    '''
    Sets up an ArgumentParser with some default flags and parses
    command_line_options.

    :return: The populated namespace from ArgumentParser.parse_args
    '''

    parser = argparse.ArgumentParser(description='{} - {}'.format(name, description))
    parser.add_argument('-V', '--version', action='version', version='{} {}'.format(name, version))
    parser.add_argument('-l', '--log_file', help='path to log file', default=None)
    parser.add_argument('-L', '--log_level', help='define the log level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default=None)
    parser.add_argument('-d', '--debug', action='store_true', default=False, help='print debug messages')
    parser.add_argument('-s', '--silent', action='store_true', default=False, help='don\'t log to command line')
    parser.add_argument('-C', '--config_file', help='set path to config File', default='{}/main.cfg'.format(get_config_dir()))
    parser.add_argument('-t', '--testing', default=False, action='store_true', help='shutdown system after one iteration')
    return parser.parse_args(command_line_options[1:])


def _get_console_output_level(debug_flag):
    if debug_flag:
        return logging.DEBUG
    return logging.INFO


def _setup_logging(config, args, component=None):
    log_level = getattr(logging, config['Logging']['logLevel'], None)
    log_format = dict(fmt='[%(asctime)s][%(module)s][%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG)

    log_file = get_log_file_for_component(component, config)
    create_dir_for_file(log_file)
    file_log = logging.FileHandler(log_file)
    file_log.setLevel(log_level)
    file_log.setFormatter(logging.Formatter(**log_format))
    logger.addHandler(file_log)

    if not args.silent:
        console_log = logging.StreamHandler()
        console_log.setLevel(_get_console_output_level(args.debug))
        console_log.setFormatter(ColoringFormatter(**log_format))
        logger.addHandler(console_log)


def get_log_file_for_component(component: str, config: ConfigParser) -> str:
    log_file = Path(config['Logging']['logFile'])
    if component is None:
        return config['Logging']['logFile']
    return f"{log_file.parent}/{log_file.stem}_{component}{log_file.suffix}"


def _load_config(args):
    '''
    Loads the config from args.config_file

    :param args: The parsed args returned from Argparser
    :return: A dictionary containing the parsed config
    '''

    config = configparser.ConfigParser()
    config.read(args.config_file)
    if args.log_file is not None:
        config['Logging']['logFile'] = args.log_file
    if args.log_level is not None:
        config['Logging']['logLevel'] = args.log_level
    return config
