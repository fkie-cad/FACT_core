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

from statistic.work_load import WorkLoadStatistic
from storage.MongoMgr import MongoMgr
from helperFunctions.program_setup import program_setup, was_started_by_start_fact

PROGRAM_NAME = 'FACT DB-Service'
PROGRAM_DESCRIPTION = 'Firmware Analysis and Compare Tool (FACT) DB-Service'


def shutdown(*_):
    global run
    logging.info('shutting down {}...'.format(PROGRAM_NAME))
    run = False


if __name__ == '__main__':
    if was_started_by_start_fact():
        signal.signal(signal.SIGUSR1, shutdown)
        signal.signal(signal.SIGINT, lambda *_: None)
    else:
        signal.signal(signal.SIGINT, shutdown)

    args, config = program_setup(PROGRAM_NAME, PROGRAM_DESCRIPTION)
    mongo_server = MongoMgr(config=config)
    work_load_stat = WorkLoadStatistic(config=config, component='database')

    run = True
    while run:
        work_load_stat.update()
        sleep(5)
        if args.testing:
            break

    work_load_stat.shutdown()
    mongo_server.shutdown()

    sys.exit()
