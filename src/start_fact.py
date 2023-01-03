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

try:
    import fact_base  # pylint: disable=unused-import  # noqa: F401  # just check if FACT is installed
except ImportError:
    sys.exit(1)

from config import cfg
from helperFunctions.fileSystem import get_src_dir
from helperFunctions.program_setup import program_setup

PROGRAM_NAME = 'FACT Starter'
PROGRAM_DESCRIPTION = 'This script starts all installed FACT components'


def _evaluate_optional_args(args: argparse.Namespace):
    optional_args = ''
    if args.debug:
        optional_args += ' -d'
    if args.silent:
        optional_args += ' -s'
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
    logging.info(f'starting {component}')
    optional_args = _evaluate_optional_args(args)
    command = f'{script_path} -l {cfg.logging.logfile} -L {cfg.logging.loglevel} -C {args.config_file} {optional_args}'
    return Popen(split(command))


def _terminate_process(process: Popen):
    if process is not None:
        try:
            os.kill(process.pid, signal.SIGUSR1)
            process.wait(timeout=60)
        except TimeoutExpired:
            logging.error('component did not stop in time -> kill')
            process.kill()
        except ProcessLookupError:
            pass


def shutdown(*_):
    logging.info('shutting down...')
    fact.run = False


def _process_is_running(process: Popen) -> bool:
    try:
        os.kill(process.pid, 0)
        if process.poll() is not None:
            return False
        return True
    except ProcessLookupError:
        return False


signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)


class FactStarter:
    run = False

    def main(self):
        self.run = True
        args = program_setup(PROGRAM_NAME, PROGRAM_DESCRIPTION)
        db_process = _start_component('db', args)
        sleep(2)
        frontend_process = _start_component('frontend', args)
        backend_process = _start_component('backend', args)
        sleep(2)
        if backend_process is not None and not _process_is_running(backend_process):
            logging.critical('Backend did not start. Shutting down...')
            self.run = False

        while self.run:
            sleep(1)
            if args.testing:
                break

        logging.debug('shutdown backend')
        _terminate_process(backend_process)
        logging.debug('shutdown frontend')
        _terminate_process(frontend_process)
        logging.debug('shutdown db')
        _terminate_process(db_process)


if __name__ == '__main__':
    fact = FactStarter()
    fact.main()
    sys.exit(0)
