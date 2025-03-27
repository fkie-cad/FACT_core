"""
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2025  Fraunhofer FKIE

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
from __future__ import annotations

import argparse
import logging
import sys
from contextlib import suppress

from common_helper_files import create_dir_for_file

import config
from helperFunctions.logging import ColoringFormatter
from version import __VERSION__


def setup_argparser(name, description, command_line_options=sys.argv, version=__VERSION__):
    """
    Sets up an ArgumentParser with some default flags and parses
    command_line_options.

    :return: The populated namespace from ArgumentParser.parse_args
    """

    parser = argparse.ArgumentParser(description=f'{name} - {description}')
    parser.add_argument('-V', '--version', action='version', version=f'{name} {version}')
    parser.add_argument('-l', '--log_file', help='path to log file', default=None)
    parser.add_argument(
        '-L',
        '--log_level',
        help='define the log level for the console',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
    )
    parser.add_argument('-C', '--config_file', help='set path to config File', default=None)
    parser.add_argument(
        '-t', '--testing', default=False, action='store_true', help='shutdown system after one iteration'
    )
    parser.add_argument('--no-radare', default=False, action='store_true', help="don't start radare server")
    return parser.parse_args(command_line_options[1:])


def _get_logging_config(args, component) -> tuple[str | None, int | None, int]:
    """
    Returns a tuple of (logfile, file_loglevel, console_loglevel) read from args and the config file.
    The loglevel is returned as an integer.
    Assumes that :py:func:`config.load` was called beforehand.
    """
    if args is None:
        return None, None, logging.INFO

    console_loglevel = logging.getLevelName(args.log_level)

    file_loglevel = logging.getLevelName(config.common.logging.level)

    if args.log_file:
        logfile = args.log_file
        # Don't crash if component is not a standard one
        with suppress(ValueError):
            setattr(config.common.logging, f'file_{component}', logfile)
    elif component not in ['frontend', 'backend', 'database']:
        logfile = f'/tmp/fact_{component}.log'
    else:
        logfile = getattr(config.common.logging, f'file_{component}')

    return logfile, file_loglevel, console_loglevel


def setup_logging(args, component):
    logfile, file_loglevel, console_loglevel = _get_logging_config(args, component)

    log_format = {'fmt': '[%(asctime)s][%(module)s][%(levelname)s]: %(message)s', 'datefmt': '%Y-%m-%d %H:%M:%S'}

    logger = logging.getLogger()
    # Pass all messages to handlers
    logger.setLevel(logging.NOTSET)

    if logfile:
        create_dir_for_file(logfile)
        file_log = logging.FileHandler(logfile)
        file_log.setLevel(file_loglevel)
        file_log.setFormatter(logging.Formatter(**log_format))
        logger.addHandler(file_log)

    console_log = logging.StreamHandler()
    console_log.setLevel(console_loglevel)
    console_log.setFormatter(ColoringFormatter(**log_format))
    logger.addHandler(console_log)
