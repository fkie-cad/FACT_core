#! /usr/bin/env python3
'''
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2018  Fraunhofer FKIE

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

from helperFunctions.fact_init import _setup_argparser, _setup_logging, _load_config
from statistic.work_load import WorkLoadStatistic
from storage.MongoMgr import MongoMgr

PROGRAM_NAME = 'FACT DB-Service'
PROGRAM_DESCRIPTION = 'Firmware Analysis and Compare Tool (FACT) DB-Service'


def shutdown(signum, frame):
    global run
    logging.info('shutting down {}...'.format(PROGRAM_NAME))
    run = False


signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)


if __name__ == '__main__':
    args = _setup_argparser(name=PROGRAM_NAME, description=PROGRAM_DESCRIPTION)
    config = _load_config(args)
    _setup_logging(config, args)
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
