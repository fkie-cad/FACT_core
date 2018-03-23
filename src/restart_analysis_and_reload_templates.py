#!/usr/bin/env python3
import logging
import sys
import time

from storage.MongoMgr import MongoMgr
from helperFunctions.program_setup import program_setup
from scheduler.Analysis import AnalysisScheduler
from scheduler.Compare import CompareScheduler

PROGRAM_NAME = 'Restart FACT Analysis Component'
PROGRAM_DESCRIPTION = 'Restart FACT Analysis Component and reload Analysis Templates'


def main(command_line_options=sys.argv):
    args, config = program_setup(PROGRAM_NAME, PROGRAM_DESCRIPTION, command_line_options=command_line_options)
    mongo_server = MongoMgr(config=config)
    analysis_service = AnalysisScheduler(config=config)
    compare_service = CompareScheduler(config=config)
    time.sleep(2)
    compare_service.shutdown()
    analysis_service.shutdown()
    logging.info('Restart Analysis component')

    if args.testing:
        logging.info('Stopping Mongo Server...')
        mongo_server.shutdown()

    return 0


if __name__ == '__main__':
    sys.exit(main())
