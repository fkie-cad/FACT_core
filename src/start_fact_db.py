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
import signal
import sys
from contextlib import suppress
from time import sleep

from docker.errors import DockerException, NotFound

from helperFunctions.program_setup import program_setup, was_started_by_start_fact
from statistic.work_load import WorkLoadStatistic
from storage.mongodb_docker import CONTAINER_IP, get_mongodb_container

PROGRAM_NAME = 'FACT DB-Service'
PROGRAM_DESCRIPTION = 'Firmware Analysis and Compare Tool (FACT) DB-Service'


class FactDb:
    def __init__(self):
        self.run = False
        self._set_signal()
        args, self.config = program_setup(PROGRAM_NAME, PROGRAM_DESCRIPTION)
        self.testing = args.testing
        self.mongodb_container = get_mongodb_container(self.config)
        self.mongo_server = None
        self.work_load_stat = None

    def _set_signal(self):
        if was_started_by_start_fact():
            signal.signal(signal.SIGUSR1, self.shutdown)
            signal.signal(signal.SIGINT, lambda *_: None)
        else:
            signal.signal(signal.SIGINT, self.shutdown)

    def shutdown(self, *_):
        logging.info('shutting down {}...'.format(PROGRAM_NAME))
        self.run = False

    def start(self):
        self.mongodb_container.start()

        logging.debug(self.mongodb_container.logs().decode())
        logging.info('Started MongoDB Docker Container with IP {}'.format(CONTAINER_IP))
        self.work_load_stat = WorkLoadStatistic(config=self.config, component='database')

        self.run = True
        while self.run:
            self.work_load_stat.update()
            sleep(5)
            if self.testing:
                break
        self.stop()

    def stop(self):
        self.work_load_stat.shutdown()
        with suppress(DockerException, NotFound):
            self.mongodb_container.stop()
            self.mongodb_container.wait(timeout=10)
            self.mongodb_container.remove()


if __name__ == '__main__':
    FactDb().start()
    sys.exit(0)
