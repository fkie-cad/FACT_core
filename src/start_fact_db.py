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
from time import sleep

from helperFunctions.program_setup import program_setup, was_started_by_start_fact
from statistic.work_load import WorkLoadStatistic
from storage.mongodb_docker import CONTAINER_IP, start_db_container
from storage.MongoMgr import MongoMgr

PROGRAM_NAME = 'FACT DB-Service'
PROGRAM_DESCRIPTION = 'Firmware Analysis and Compare Tool (FACT) DB-Service'


class FactDb:
    def __init__(self):
        self.run = False
        self._set_signal()
        args, self.config = program_setup(PROGRAM_NAME, PROGRAM_DESCRIPTION)
        self.testing = args.testing

        MongoMgr(self.config).check_file_and_directory_existence_and_permissions()
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
        with start_db_container(self.config):
            logging.info('Started MongoDB Docker Container with IP {}'.format(CONTAINER_IP))
            self.work_load_stat = WorkLoadStatistic(config=self.config, component='database')
            self.run = True

            while self.run:
                self.work_load_stat.update()
                sleep(5)
                if self.testing:
                    break

            self.work_load_stat.shutdown()


if __name__ == '__main__':
    FactDb().start()
    sys.exit(0)
