#! /usr/bin/env python3
'''
This is the FACT main script to start the frontend
'''

import logging
import pickle
import signal
import sys
import tempfile
from subprocess import Popen, TimeoutExpired
from time import sleep

from faf_init import _setup_logging, _setup_argparser, _load_config
from helperFunctions.config import get_config_dir
from helperFunctions.fileSystem import get_src_dir
from statistic.work_load import WorkLoadStatistic

PROGRAM_NAME = 'FACT Frontend'
PROGRAM_DESCRIPTION = 'Firmware Analysis and Compare Tool Frontend'


def shutdown(*_):
    global run
    logging.debug('shutting down frontend')
    run = False


def _shutdown_uwsgi_server(process):
    try:
        process.wait(timeout=30)
    except TimeoutExpired:
        logging.error('frontend did not stop in time -> kill')
        process.kill()


signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)


def start_uwsgi_server(config_path=None):
    config_parameter = ' --pyargv {}'.format(config_path) if config_path else ''
    p = Popen('(cd {} && uwsgi --ini  {}/uwsgi_config.ini{})'.format(get_src_dir(), get_config_dir(), config_parameter), shell=True)
    return p


if __name__ == '__main__':
    run = True
    args = _setup_argparser(name=PROGRAM_NAME, description=PROGRAM_DESCRIPTION)
    config = _load_config(args)
    _setup_logging(config, args)
    work_load_stat = WorkLoadStatistic(config=config, component='frontend')

    with tempfile.NamedTemporaryFile() as fp:
        fp.write(pickle.dumps(args))
        fp.flush()
        uwsgi_process = start_uwsgi_server(fp.name)

        while run:
            work_load_stat.update()
            sleep(5)

        work_load_stat.shutdown()
        _shutdown_uwsgi_server(uwsgi_process)
    sys.exit()
