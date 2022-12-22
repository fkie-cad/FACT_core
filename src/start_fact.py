#! /usr/bin/env python3
'''
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2023  Fraunhofer FKIE

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
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
from pathlib import Path
from shlex import split
from subprocess import Popen, TimeoutExpired
from time import sleep

import config
from config import cfg

try:
    import fact_base  # pylint: disable=unused-import  # noqa: F401  # just check if FACT is installed
except ImportError:
    sys.exit(1)

from helperFunctions.fileSystem import get_src_dir
from helperFunctions.program_setup import setup_argparser

PROGRAM_NAME = 'FACT Starter'
PROGRAM_DESCRIPTION = 'This script starts all installed FACT components'


def _evaluate_optional_args(args: argparse.Namespace):
    optional_args = ''
    if args.testing:
        optional_args += ' -t'
    if args.no_radare:
        optional_args += ' --no-radare'
    return optional_args


def _start_component(component: str, args: argparse.Namespace) -> Popen | None:
    script_path = Path(get_src_dir()) / f'../start_fact_{component}'
    if not script_path.exists():
        logging.debug(f'{component} not installed')
        return None
    optional_args = _evaluate_optional_args(args)
    command = f'''{script_path} \
        -l {getattr(cfg.logging, f"logfile_{component}")} \
        -L {cfg.logging.loglevel} \
        {optional_args} \
        '''

    if args.config_file is not None:
        command += f'-C {args.config_file}'

    return Popen(split(command))


def _terminate_process(process: Popen | None):
    if process is not None:
        try:
            os.kill(process.pid, signal.SIGUSR1)
            process.wait(timeout=60)
        except TimeoutExpired:
            process.kill()
        except ProcessLookupError:
            pass


def shutdown(*_):
    global run
    run = False


signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)


if __name__ == '__main__':
    run = True
    args = setup_argparser(PROGRAM_NAME, PROGRAM_DESCRIPTION)
    config.load(args.config_file)

    db_process = _start_component('database', args)
    frontend_process = _start_component('frontend', args)
    backend_process = _start_component('backend', args)

    while run:
        sleep(1)
        if args.testing:
            break

    _terminate_process(backend_process)
    _terminate_process(frontend_process)
    _terminate_process(db_process)

    sys.exit()
