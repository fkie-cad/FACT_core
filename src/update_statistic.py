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
import sys

from helperFunctions.fact_init import setup_argparser, setup_logging, load_config
from storage.MongoMgr import MongoMgr
from statistic.update import StatisticUpdater

PROGRAM_NAME = 'FACT Statistic Updater'
PROGRAM_DESCRIPTION = 'Initialize or update FACT statistic'


if __name__ == '__main__':
    args = setup_argparser(PROGRAM_NAME, PROGRAM_DESCRIPTION)
    config = load_config(args)
    setup_logging(args)

    logging.info('Try to start Mongo Server...')
    mongo_server = MongoMgr(config=config)

    updater = StatisticUpdater(config=config)
    updater.update_all_stats()
    updater.shutdown()

    if args.testing:
        logging.info('Stopping Mongo Server...')
        mongo_server.shutdown()

    sys.exit()
