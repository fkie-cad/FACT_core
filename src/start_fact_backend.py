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

from fact_base import FactBase

from analysis.PluginBase import PluginInitException
from helperFunctions.process import complete_shutdown
from intercom.back_end_binding import InterComBackEndBinding
from scheduler.Analysis import AnalysisScheduler
from scheduler.Compare import CompareScheduler
from scheduler.Unpacking import UnpackingScheduler


class FactBackend(FactBase):
    PROGRAM_NAME = 'FACT Backend'
    PROGRAM_DESCRIPTION = 'Firmware Analysis and Compare Tool (FACT) Backend'
    COMPONENT = 'backend'

    def __init__(self):
        super().__init__()

        try:
            self.analysis_service = AnalysisScheduler(config=self.config)
        except PluginInitException as error:
            logging.critical(f'Error during initialization of plugin {error.plugin.NAME}. Shutting down FACT backend')
            complete_shutdown()
        self.unpacking_service = UnpackingScheduler(
            config=self.config,
            post_unpack=self.analysis_service.start_analysis_of_object,
            analysis_workload=self.analysis_service.get_scheduled_workload
        )
        self.compare_service = CompareScheduler(config=self.config)
        self.intercom = InterComBackEndBinding(
            config=self.config,
            analysis_service=self.analysis_service,
            compare_service=self.compare_service,
            unpacking_service=self.unpacking_service
        )

    def main(self):
        while self.run:
            self.work_load_stat.update(
                unpacking_workload=self.unpacking_service.get_scheduled_workload(),
                analysis_workload=self.analysis_service.get_scheduled_workload()
            )
            if self._exception_occurred():
                break
            sleep(5)
            if self.args.testing:
                break

        self.shutdown()

    def shutdown(self):
        super().shutdown()
        self.intercom.shutdown()
        self.compare_service.shutdown()
        self.unpacking_service.shutdown()
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
