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
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Process
from time import sleep

from helperFunctions.process import complete_shutdown
from helperFunctions.program_setup import program_setup
from intercom.back_end_binding import InterComBackEndBinding
from scheduler.Analysis import AnalysisScheduler
from scheduler.Compare import CompareScheduler
from scheduler.Unpacking import UnpackingScheduler
from scheduler.analysis_tag import TaggingDaemon
from statistic.work_load import WorkLoadStatistic
from worker import analysis_worker

PROGRAM_NAME = 'FACT Backend'
PROGRAM_DESCRIPTION = 'Firmware Analysis and Compare Tool (FACT) Backend'
RUN = True


def shutdown(*_, **__):
    global RUN  # pylint: disable=global-statement
    logging.info('shutting down {}...'.format(PROGRAM_NAME))
    RUN = False


signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)


def join_worker(workers):
    with ThreadPoolExecutor() as pool:
        for worker in workers:
            pool.submit(worker.terminate)
    for worker in workers:
        worker.join()


def spawn_worker(config, workers):
    for index in range(config.getint('Analysis', 'worker', fallback=1)):
        worker = Process(target=analysis_worker, args=(index,))
        worker.start()
        workers.append(worker)


def main():
    global RUN  # pylint: disable=global-statement
    args, config = program_setup(PROGRAM_NAME, PROGRAM_DESCRIPTION)
    workers = list()
    analysis_service = AnalysisScheduler(config=config)
    spawn_worker(config, workers)
    tagging_service = TaggingDaemon(analysis_scheduler=analysis_service)
    unpacking_service = UnpackingScheduler(config=config, post_unpack=analysis_service.add_task,
                                           analysis_workload=analysis_service.get_scheduled_workload)
    compare_service = CompareScheduler(config=config)
    intercom = InterComBackEndBinding(config=config, analysis_service=analysis_service, compare_service=compare_service,
                                      unpacking_service=unpacking_service)
    work_load_stat = WorkLoadStatistic(config=config)
    while RUN:
        work_load_stat.update(unpacking_workload=unpacking_service.get_scheduled_workload(),
                              analysis_workload=analysis_service.get_scheduled_workload())
        if any((unpacking_service.check_exceptions(), compare_service.check_exceptions(),
                analysis_service.check_exceptions())):
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
    join_worker(workers)
    analysis_service.shutdown()
    if not args.testing:
        complete_shutdown()

    return 0


if __name__ == '__main__':
    exit(main())
