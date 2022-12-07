import logging
import os
import signal
from time import sleep

try:
    import psutil
    import psycopg2  # pylint: disable=unused-import  # noqa: F401  # new dependency of FACT>=4.0

    from helperFunctions.program_setup import program_setup
    from statistic.work_load import WorkLoadStatistic
except (ImportError, ModuleNotFoundError):
    logging.exception(
        'Could not load dependencies. Please make sure that you have installed FACT correctly '
        '(see INSTALL.md for more information). If you recently updated FACT, you may want to rerun the installation.'
    )
    logging.warning(
        'The database of FACT switched from MongoDB to PostgreSQL with the release of FACT 4.0. '
        'For instructions on how to upgrade FACT and how to migrate your database see '
        'https://fkie-cad.github.io/FACT_core/migration.html'
    )
    raise


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
            signal.signal(signal.SIGTERM, lambda *_: None)
            os.setpgid(os.getpid(), os.getpid())  # reset pgid to self so that "complete_shutdown" doesn't run amok
        else:
            signal.signal(signal.SIGINT, self.shutdown_listener)
            signal.signal(signal.SIGTERM, self.shutdown_listener)

        self.args = program_setup(self.PROGRAM_NAME, self.PROGRAM_DESCRIPTION, self.COMPONENT)
        self.work_load_stat = WorkLoadStatistic(component=self.COMPONENT)

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
