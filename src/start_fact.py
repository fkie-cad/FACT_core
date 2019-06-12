#! /usr/bin/env python3
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

import logging
import os
import signal
import sys
from shlex import split
from subprocess import Popen, TimeoutExpired
from time import sleep

from helperFunctions.program_setup import program_setup
from helperFunctions.config import get_src_dir

PROGRAM_NAME = 'FACT Starter'
PROGRAM_DESCRIPTION = 'This script starts all installed FACT components'


def _evaluate_optional_args(args):
    optional_args = ''
    if args.debug:
        optional_args += ' -d'
    if args.silent:
        optional_args += ' -s'
    if args.testing:
        optional_args += ' -t'
    return optional_args


def _start_component(component, args):
    script_path = os.path.join(get_src_dir(), '../start_fact_{}'.format(component))
    if os.path.exists(script_path):
        logging.info('starting {}'.format(component))
        optional_args = _evaluate_optional_args(args)
        command = '{} -l {} -L {} -C {} {}'.format(
            script_path, config['Logging']['logFile'], config['Logging']['logLevel'], args.config_file, optional_args
        )
        p = Popen(split(command))
        return p
    else:
        logging.debug('{} not installed'.format(component))
        return None


def _terminate_process(process: Popen):
    if process is not None:
        os.kill(process.pid, signal.SIGUSR1)
        try:
            process.wait(timeout=60)
        except TimeoutExpired:
            logging.error('component did not stop in time -> kill')
            process.kill()


def shutdown(*_):
    global run
    logging.info('shutting down...')
    run = False


signal.signal(signal.SIGINT, shutdown)

if __name__ == '__main__':
    process_list = []
    run = True
    args, config = program_setup(PROGRAM_NAME, PROGRAM_DESCRIPTION)

    db_process = _start_component('db', args)
    sleep(2)
    frontend_process = _start_component('frontend', args)
    backend_process = _start_component('backend', args)

    while run:
        sleep(1)
        if args.testing:
            break

    logging.debug('shutdown backend')
    _terminate_process(backend_process)
    logging.debug('shutdown frontend')
    _terminate_process(frontend_process)
    logging.debug('shutdown db')
    _terminate_process(db_process)

    sys.exit()
