#! /usr/bin/env python3
'''
This is the FAF main script to start the db
'''

import logging
import signal
import sys
from time import sleep

from faf_init import _setup_argparser, _setup_logging, _load_config
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

    work_load_stat.shutdown()
    mongo_server.shutdown()

    sys.exit()
