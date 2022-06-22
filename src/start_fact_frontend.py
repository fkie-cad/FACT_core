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

import logging
import pickle
import signal
import sys
import tempfile
from shlex import split
from subprocess import Popen, TimeoutExpired

from helperFunctions.config import get_config_dir
from helperFunctions.fileSystem import get_src_dir
from helperFunctions.install import run_cmd_with_logging
from helperFunctions.program_setup import program_setup
from statistic.work_load import WorkLoadStatistic

COMPOSE_YAML = f'{get_src_dir()}/install/radare/docker-compose.yml'


class UwsgiServer:
    def __init__(self, config_path: str = None):
        self.config_path = config_path
        self.process = None

    def start(self):
        config_parameter = f' --pyargv {self.config_path}' if self.config_path else ''
        command = f'uwsgi --thunder-lock --ini  {get_config_dir()}/uwsgi_config.ini{config_parameter}'
        self.process = Popen(split(command), cwd=get_src_dir())  # pylint: disable=consider-using-with

    def shutdown(self):
        if self.process:
            try:
                self.process.send_signal(signal.SIGINT)
                self.process.wait(timeout=30)
            except TimeoutExpired:
                logging.error('frontend did not stop in time -> kill')
                self.process.kill()


class FactFrontend:
    PROGRAM_NAME = 'FACT Frontend'
    PROGRAM_DESCRIPTION = 'Firmware Analysis and Compare Tool Frontend'
    COMPONENT = 'frontend'

    def __init__(self):
        self.args, self.config = program_setup(self.PROGRAM_NAME, self.PROGRAM_DESCRIPTION, self.COMPONENT)

        self.work_load_stat = WorkLoadStatistic(config=self.config, component=self.COMPONENT)

        self.fp = tempfile.NamedTemporaryFile()
        self.fp.write(pickle.dumps(self.args))
        self.fp.flush()
        self.server = UwsgiServer(self.fp.name)

        self.run = False

    def start(self):
        self.run = True

        signal.signal(signal.SIGINT, signal.SIG_IGN)
        self.server.start()
        self.work_load_stat.start()
        run_cmd_with_logging(f'docker-compose -f {COMPOSE_YAML} up -d')

        signal.signal(signal.SIGINT, self._shutdown_listener)
        signal.signal(signal.SIGTERM, self._shutdown_listener)

    def shutdown(self):
        self.run = False
        self.work_load_stat.shutdown()
        self.server.shutdown()
        self.fp.close()
        run_cmd_with_logging(f'docker-compose -f {COMPOSE_YAML} down')

    def _shutdown_listener(self, signum, _):
        logging.info(f'Received signal {signum}. Shutting down {self.PROGRAM_NAME}...')
        self.shutdown()

    def main(self):
        self.start()
        logging.info(f'Successfully started {self.PROGRAM_NAME}')

        while self.run:
            signal.pause()

        self.shutdown()


if __name__ == '__main__':
    FactFrontend().main()
    sys.exit(0)
