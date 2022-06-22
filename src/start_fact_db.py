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
import signal
import sys

from sqlalchemy.exc import SQLAlchemyError

from helperFunctions.program_setup import program_setup
from statistic.work_load import WorkLoadStatistic
from storage.db_interface_base import ReadOnlyDbInterface


class FactDb:
    PROGRAM_NAME = 'FACT DB-Service'
    PROGRAM_DESCRIPTION = 'Firmware Analysis and Compare Tool (FACT) DB-Service'
    COMPONENT = 'database'

    def __init__(self):
        _, config = program_setup(self.PROGRAM_NAME, self.PROGRAM_DESCRIPTION, self.COMPONENT)
        self.run = False
        self._check_postgres_connection(config)
        self.work_load_stat = WorkLoadStatistic(config=config, component=self.COMPONENT)

    def _shutdown_listener(self, signum, _):
        logging.info(f'Received signal {signum}. Shutting down {self.PROGRAM_NAME}...')
        self.shutdown()

    def start(self):
        self.run = True

        signal.signal(signal.SIGINT, signal.SIG_IGN)
        self.work_load_stat.start()

        signal.signal(signal.SIGINT, self._shutdown_listener)
        signal.signal(signal.SIGTERM, self._shutdown_listener)

    def shutdown(self):
        self.run = False
        self.work_load_stat.shutdown()

    def main(self):
        self.start()
        while self.run:
            signal.pause()

    @staticmethod
    def _check_postgres_connection(config):
        try:
            ReadOnlyDbInterface(config=config).connection.engine.connect()
        except (SQLAlchemyError, ModuleNotFoundError):  # ModuleNotFoundError should handle missing psycopg2
            logging.exception('Could not connect to PostgreSQL. Is the service running?')
            sys.exit(1)


if __name__ == '__main__':
    FactDb().main()
    sys.exit(0)
