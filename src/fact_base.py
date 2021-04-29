import logging
from time import sleep

from helperFunctions.program_setup import program_setup, set_signals
from statistic.work_load import WorkLoadStatistic


class FactBase:
    PROGRAM_NAME = 'FACT Base'
    PROGRAM_DESCRIPTION = ''
    COMPONENT = 'base'

    def __init__(self):
        self.run = True
        set_signals(self.shutdown_listener)
        self.args, self.config = program_setup(self.PROGRAM_NAME, self.PROGRAM_DESCRIPTION)
        self.work_load_stat = WorkLoadStatistic(config=self.config, component=self.COMPONENT)

    def shutdown_listener(self, signum, _):
        logging.info(f'Received signal {signum}. Shutting down {self.PROGRAM_NAME}...')
        self.run = False

    def shutdown(self):
        logging.info(f'Shutting down components of {self.PROGRAM_NAME}')
        self.work_load_stat.shutdown()

    def main(self):
        while self.run:
            self.work_load_stat.update()
            sleep(5)
            if self.args.testing:
                break
        self.shutdown()
