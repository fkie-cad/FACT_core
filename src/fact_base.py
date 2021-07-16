import logging
import os
import signal
from time import sleep

import psutil

from helperFunctions.program_setup import program_setup
from statistic.work_load import WorkLoadStatistic


class FactBase:
    PROGRAM_NAME = 'FACT Base'
    PROGRAM_DESCRIPTION = ''
    COMPONENT = 'base'

    def __init__(self):
        self.run = True
        # Check whether the process was started by start_fact.py
        parent = ' '.join(psutil.Process(os.getppid()).cmdline())
        started_by_start_fact_py = 'start_fact.py' in parent or 'start_all_installed_fact_components' in parent

        if started_by_start_fact_py:
            signal.signal(signal.SIGUSR1, self.shutdown_listener)
            signal.signal(signal.SIGINT, lambda *_: None)
            os.setpgid(os.getpid(), os.getpid())  # reset pgid to self so that "complete_shutdown" doesn't run amok
        else:
            signal.signal(signal.SIGINT, self.shutdown_listener)

        self.args, self.config = program_setup(self.PROGRAM_NAME, self.PROGRAM_DESCRIPTION, self.COMPONENT)
        self.work_load_stat = WorkLoadStatistic(config=self.config, component=self.COMPONENT)

    def shutdown_listener(self, signum, _):
        logging.info(f'Received signal {signum}. Shutting down {self.PROGRAM_NAME}...')
        self.run = False

    def shutdown(self):
        logging.info(f'Shutting down components of {self.PROGRAM_NAME}')
        self.work_load_stat.shutdown()

    def main(self):
        logging.info(f'Successfully started {self.PROGRAM_NAME}')
        while self.run:
            self.work_load_stat.update()
            sleep(5)
            if self.args.testing:
                break
        self.shutdown()
