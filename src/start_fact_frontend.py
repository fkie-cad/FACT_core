#! /usr/bin/env python3
'''
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2020  Fraunhofer FKIE

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
import pickle
import signal
import sys
import tempfile
from shlex import split
from subprocess import Popen, TimeoutExpired
from time import sleep

from common_helper_process import execute_shell_command

from helperFunctions.config import get_config_dir
from helperFunctions.fileSystem import get_src_dir
from helperFunctions.program_setup import program_setup, was_started_by_start_fact
from install.frontend import COMPOSE_VENV
from statistic.work_load import WorkLoadStatistic

PROGRAM_NAME = 'FACT Frontend'
PROGRAM_DESCRIPTION = 'Firmware Analysis and Compare Tool Frontend'


def shutdown(*_):
    global run  # pylint: disable=invalid-name,global-statement
    logging.debug('shutting down frontend')
    run = False


def _shutdown_uwsgi_server(process):
    try:
        process.wait(timeout=30)
    except TimeoutExpired:
        logging.error('frontend did not stop in time -> kill')
        process.kill()


def start_uwsgi_server(config_path=None):
    config_parameter = ' --pyargv {}'.format(config_path) if config_path else ''
    command = 'uwsgi --thunder-lock --ini  {}/uwsgi_config.ini{}'.format(get_config_dir(), config_parameter)
    process = Popen(split(command), cwd=get_src_dir())
    return process


def start_docker():
    execute_shell_command('{} -f {}/install/radare/docker-compose.yml up -d'.format(COMPOSE_VENV / 'bin' / 'docker-compose', get_src_dir()))


def stop_docker():
    execute_shell_command('{} -f {}/install/radare/docker-compose.yml down'.format(COMPOSE_VENV / 'bin' / 'docker-compose', get_src_dir()))


if __name__ == '__main__':
    if was_started_by_start_fact():
        signal.signal(signal.SIGUSR1, shutdown)
        signal.signal(signal.SIGINT, lambda *_: None)
    else:
        signal.signal(signal.SIGINT, shutdown)

    run = True  # pylint: disable=invalid-name
    ARGS, CONFIG = program_setup(PROGRAM_NAME, PROGRAM_DESCRIPTION)

    start_docker()

    work_load_stat = WorkLoadStatistic(config=CONFIG, component='frontend')

    with tempfile.NamedTemporaryFile() as fp:
        fp.write(pickle.dumps(ARGS))
        fp.flush()
        uwsgi_process = start_uwsgi_server(fp.name)

        while run:
            work_load_stat.update()
            sleep(5)
            if ARGS.testing:
                break

        work_load_stat.shutdown()
        _shutdown_uwsgi_server(uwsgi_process)

    stop_docker()

    sys.exit()
