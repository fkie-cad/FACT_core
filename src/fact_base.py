import logging
import os
import signal
import sys
from pathlib import Path
from shlex import split
from subprocess import CalledProcessError, PIPE, run, STDOUT
from time import sleep

import config

try:
    import psutil
    import psycopg2  # noqa: F401

    from helperFunctions.program_setup import setup_argparser, setup_logging
    from statistic.work_load import WorkLoadStatistic
    from storage.db_interface_base import DbInterfaceError
    from storage.migration import db_needs_migration
    from version import __VERSION__
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

        self.args = setup_argparser(self.PROGRAM_NAME, self.PROGRAM_DESCRIPTION)
        config.load(self.args.config_file)
        setup_logging(self.args, self.COMPONENT)
        python_version, *_ = sys.version.split(' ')
        logging.info(
            f'Starting {self.PROGRAM_NAME} @ {__VERSION__} ({self._get_git_revision()}, Python {python_version})'
        )
        self.do_self_test()

        self._register_signal_handlers()
        self.work_load_stat = WorkLoadStatistic(component=self.COMPONENT)

    @staticmethod
    def _get_git_revision() -> str:
        try:
            proc = run(split('git rev-parse --short HEAD'), stdout=PIPE, stderr=STDOUT, cwd=Path(__file__).parent)
            return proc.stdout.decode().strip()
        except CalledProcessError:
            return 'unknown revision'

    def _register_signal_handlers(self):
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

    def shutdown_listener(self, signum, _):
        if not _is_main_process():
            return  # all subprocesses also inherit this signal handler (which is intentional for a "clean" shutdown)
        logging.info(f'Received signal {signum}. Shutting down {self.PROGRAM_NAME}...')
        self.run = False

    def start(self):
        pass

    def _update_component_workload(self):
        self.work_load_stat.update()

    def shutdown(self):
        logging.info(f'Shutting down components of {self.PROGRAM_NAME}')
        self.work_load_stat.shutdown()

    def main(self):
        self.start()
        logging.info(f'Successfully started {self.PROGRAM_NAME}')
        counter = 0
        while self.run:
            self._update_component_workload()
            sleep(5)
            if self.args.testing:
                break
            if not counter % 12:  # only check every minute
                _check_memory_usage()
            counter += 1
        self.shutdown()

    @staticmethod
    def do_self_test():
        if db_needs_migration():
            logging.error(
                'The database schema in "storage/schema.py" does not match the schema of the configured database. '
                'Please run `alembic upgrade head` from `src` to update the schema.'
            )
            raise DbInterfaceError('Schema mismatch')


def _check_memory_usage():
    memory_usage = psutil.virtual_memory().percent
    if memory_usage > 95.0:  # noqa: PLR2004
        logging.critical(f'System memory is critically low: {memory_usage}%')
    elif memory_usage > 80.0:  # noqa: PLR2004
        logging.warning(f'System memory is running low: {memory_usage}%')
    else:
        logging.info(f'System memory usage: {memory_usage}%')


def _is_main_process() -> bool:
    return os.getpid() == os.getpgrp()
