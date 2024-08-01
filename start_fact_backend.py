#! /usr/bin/env python3
"""
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2024  Fraunhofer FKIE

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
"""

import grp
import logging
import os
import resource
import sys
from pathlib import Path

from fact import config
from fact.analysis.PluginBase import PluginInitException
from fact.fact_base import FactBase
from fact.helperFunctions.process import complete_shutdown
from fact.intercom.back_end_binding import InterComBackEndBinding
from fact.scheduler.analysis import AnalysisScheduler
from fact.scheduler.comparison_scheduler import ComparisonScheduler
from fact.scheduler.unpacking_scheduler import UnpackingScheduler
from fact.storage.unpacking_locks import UnpackingLockManager

ULIMIT_MIN = 1_024


class FactBackend(FactBase):
    PROGRAM_NAME = 'FACT Backend'
    PROGRAM_DESCRIPTION = 'Firmware Analysis and Compare Tool (FACT) Backend'
    COMPONENT = 'backend'

    def __init__(self):
        super().__init__()
        self.unpacking_lock_manager = UnpackingLockManager()
        self._create_docker_base_dir()
        _check_ulimit()

        try:
            self.analysis_service = AnalysisScheduler(unpacking_locks=self.unpacking_lock_manager)
        except PluginInitException as error:
            logging.critical(f'Error during initialization of plugin {error.plugin.NAME}: {error}.')
            complete_shutdown()
        self.unpacking_service = UnpackingScheduler(
            post_unpack=self.analysis_service.start_analysis_of_object,
            analysis_workload=self.analysis_service.get_combined_analysis_workload,
            unpacking_locks=self.unpacking_lock_manager,
        )
        self.compare_service = ComparisonScheduler()
        self.intercom = InterComBackEndBinding(
            analysis_service=self.analysis_service,
            compare_service=self.compare_service,
            unpacking_service=self.unpacking_service,
            unpacking_locks=self.unpacking_lock_manager,
        )

    def start(self):
        self.analysis_service.start()
        self.unpacking_service.start()
        self.compare_service.start()
        self.intercom.start()

    def shutdown(self):
        super().shutdown()
        self.intercom.shutdown()
        self.compare_service.shutdown()
        self.unpacking_service.shutdown()
        self.analysis_service.shutdown()
        self.unpacking_lock_manager.shutdown()
        if not self.args.testing:
            complete_shutdown()

    def _update_component_workload(self):
        self.work_load_stat.update(
            unpacking_workload=self.unpacking_service.get_scheduled_workload(),
            analysis_workload=self.analysis_service.get_scheduled_workload(),
        )

    @staticmethod
    def _create_docker_base_dir():
        docker_mount_base_dir = Path(config.backend.docker_mount_base_dir)
        docker_mount_base_dir.mkdir(0o770, exist_ok=True)
        docker_gid = grp.getgrnam('docker').gr_gid
        try:
            os.chown(docker_mount_base_dir, -1, docker_gid)
        except PermissionError:
            # If we don't have enough rights to change the permissions we assume they are right
            # E.g. in FACT_docker the correct group is not the group named 'docker'
            logging.warning('Could not change permissions of docker-mount-base-dir. Ignoring.')

    def _exception_occurred(self):
        return any(
            (
                self.unpacking_service.check_exceptions(),
                self.compare_service.check_exceptions(),
                self.analysis_service.check_exceptions(),
            )
        )


def _check_ulimit():
    """
    2024-07-16 - the numbers are prone to change over time

    Each process has a hard limit and a soft limit for the maximum number of file descriptors (FDs) opened at the same
    time. Since FACT makes extensive use of multiprocessing features, it uses up a lot of those FDs and if we run out,
    this raises an OSError. To mitigate this, we try to increase the soft limit and print a warning if the hard limit
    is low. With the default configuration, FACT uses 556 FDs (and potentially many more if you crank up the worker
    counts).

    The FD number is distributed among the individual backend components as follows:

    | component              | init | start | sum |
    | ---------------------- | ---- | ----- | --- |
    | fact_base              | 7    | -     | 7   |
    | unpacking_lock_manager | 2    | -     | 2   |
    | analysis_service       | 200  | 294   | 494 |
    | unpacking_service      | 2    | 20    | 22  |
    | compare_service        | 3    | 4     | 7   |
    | intercom               | -    | 24    | 24  |
    | total                  |      |       | 556 |

    Most of this stems from the analysis_service. The analysis service in turn looks like this:

    | component                | init | start | sum |
    | ------------------------ | ---- | ----- | --- |
    | plugins                  | 196  | 268   |     |
    | process queue            | 2    | -     |     |
    | AnalysisStatus           | 2    | 2     |     |
    | AnalysisTaskScheduler    | -    | -     |     |
    | FSOrganizer              | -    | -     |     |
    | BackendDbInterface       | -    | -     |     |
    | scheduler processes (4x) | -    | 16    |     |
    | collector processes (2x) | -    | 8     |     |
    | total                    | 200  | 294   | 494 |

    The 29 plugins are the main source of used FDs. Many FDs are used during initialization. The main reason for this
    are input and output queues. Each queue contributes two FDs. In addition to that, there are the manager processes
    for passing data between processes which also consume two FDs. Then there are some more multiprocessing objects
    (Values, Arrays, etc.) that add some more. Even more are used when the worker processes are started.
    """
    soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard_limit < ULIMIT_MIN:
        logging.warning(
            'The open file limit appears to be low. This could lead to "too many open files" errors. Please increase '
            'the open file hard limit for the process that runs FACT.'
        )
    if soft_limit < hard_limit:
        # we are only allowed to increase the soft limit and not the hard limit
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard_limit, hard_limit))


if __name__ == '__main__':
    backend = FactBackend()
    try:
        backend.main()
        sys.exit(0)
    except OSError as error:
        logging.exception(f'Exception during start: {error}')
        backend.shutdown()
        sys.exit(1)
