#! /usr/bin/env python3
'''
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2021  Fraunhofer FKIE

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
from time import sleep

from analysis.PluginBase import PluginInitException
from helperFunctions.process import complete_shutdown
from helperFunctions.program_setup import program_setup, set_signals
from intercom.back_end_binding import InterComBackEndBinding
from scheduler.Analysis import AnalysisScheduler
from scheduler.analysis_tag import TaggingDaemon
from scheduler.Compare import CompareScheduler
from scheduler.Unpacking import UnpackingScheduler
from statistic.work_load import WorkLoadStatistic


class FactBackend:  # pylint: disable=too-many-instance-attributes
    PROGRAM_NAME = 'FACT Backend'
    PROGRAM_DESCRIPTION = 'Firmware Analysis and Compare Tool (FACT) Backend'

    def __init__(self):
        self.run = True
        set_signals(self.shutdown_listener)
        self.args, config = program_setup(self.PROGRAM_NAME, self.PROGRAM_DESCRIPTION)

        try:
            self.analysis_service = AnalysisScheduler(config=config)
        except PluginInitException as error:
            logging.critical('Error during initialization of plugin {}. Shutting down FACT backend'.format(error.plugin.NAME))
            complete_shutdown()
        self.tagging_service = TaggingDaemon(analysis_scheduler=self.analysis_service)
        self.unpacking_service = UnpackingScheduler(
            config=config,
            post_unpack=self.analysis_service.start_analysis_of_object,
            analysis_workload=self.analysis_service.get_scheduled_workload
        )
        self.compare_service = CompareScheduler(config=config)
        self.intercom = InterComBackEndBinding(
            config=config,
            analysis_service=self.analysis_service,
            compare_service=self.compare_service,
            unpacking_service=self.unpacking_service
        )
        self.work_load_stats = WorkLoadStatistic(config=config)

    def shutdown_listener(self, signum, _):
        logging.info('received {signum}. shutting down {name}...'.format(signum=signum, name=self.PROGRAM_NAME))
        self.run = False

    def main(self):
        while self.run:
            self.work_load_stats.update(
                unpacking_workload=self.unpacking_service.get_scheduled_workload(),
                analysis_workload=self.analysis_service.get_scheduled_workload()
            )
            if self._exception_occurred():
                break
            sleep(5)
            if self.args.testing:
                break

        self._shutdown()

    def _shutdown(self):
        logging.info('Shutting down components')
        self.work_load_stats.shutdown()
        self.intercom.shutdown()
        self.compare_service.shutdown()
        self.unpacking_service.shutdown()
        self.tagging_service.shutdown()
        self.analysis_service.shutdown()
        if not self.args.testing:
            complete_shutdown()

    def _exception_occurred(self):
        return any((
            self.unpacking_service.check_exceptions(),
            self.compare_service.check_exceptions(),
            self.analysis_service.check_exceptions()
        ))


if __name__ == '__main__':
    FactBackend().main()
