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
from time import sleep

from helperFunctions.process import complete_shutdown
from helperFunctions.program_setup import program_setup
from intercom.back_end_binding import InterComBackEndBinding
from scheduler.Analysis import AnalysisScheduler
from scheduler.Compare import CompareScheduler
from scheduler.Unpacking import UnpackingScheduler
from scheduler.analysis_tag import TaggingDaemon
from statistic.work_load import WorkLoadStatistic

PROGRAM_NAME = 'FACT Backend'
PROGRAM_DESCRIPTION = 'Firmware Analysis and Compare Tool (FACT) Backend'


def shutdown(signum, frame):
    global run
    logging.info('shutting down {}...'.format(PROGRAM_NAME))
    run = False


signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)


if __name__ == '__main__':
    args, config = program_setup(PROGRAM_NAME, PROGRAM_DESCRIPTION)
    analysis_service = AnalysisScheduler(config=config)
    tagging_service = TaggingDaemon(analysis_scheduler=analysis_service)
    unpacking_service = UnpackingScheduler(config=config, post_unpack=analysis_service.add_task, analysis_workload=analysis_service.get_scheduled_workload)
    compare_service = CompareScheduler(config=config)
    intercom = InterComBackEndBinding(config=config, analysis_service=analysis_service, compare_service=compare_service, unpacking_service=unpacking_service)
    work_load_stat = WorkLoadStatistic(config=config)

    run = True
    while run:
        work_load_stat.update(unpacking_workload=unpacking_service.get_scheduled_workload(), analysis_workload=analysis_service.get_scheduled_workload())
        if any((unpacking_service.check_exceptions(), compare_service.check_exceptions(), analysis_service.check_exceptions())):
            break
        sleep(5)
        if args.testing:
            break

    logging.info('shutdown components')
    work_load_stat.shutdown()
    intercom.shutdown()
    compare_service.shutdown()
    unpacking_service.shutdown()
    tagging_service.shutdown()
    analysis_service.shutdown()
    if not args.testing:
        complete_shutdown()
