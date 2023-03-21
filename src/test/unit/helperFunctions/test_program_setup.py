import logging
from pathlib import Path

from helperFunctions.program_setup import _get_logging_config, setup_logging
from test.common_helper import get_test_data_dir  # pylint: disable=wrong-import-order


class ArgumentMock:
    config_file = get_test_data_dir() + '/load_cfg_test'
    log_file = '/tmp/fact_test_argument_log_file.log'
    log_level = 'DEBUG'
    silent = False
    debug = False


config_mock = {
    'logging': {
        'logfile-frontend': '/tmp/fact_test_frontend.log',
        'logfile-backend': '/tmp/fact_test_backend.log',
        'logfile-database': '/tmp/fact_test_database.log',
        'loglevel': 'DEBUG',
    }
}


def test_get_logging_config(cfg_tuple):
    cfg, _ = cfg_tuple
    logfile, file_loglevel, console_loglevel = _get_logging_config(ArgumentMock, 'frontend')
    assert logfile == ArgumentMock.log_file
    assert console_loglevel == logging.getLevelName(ArgumentMock.log_level)
    assert file_loglevel == logging.getLevelName(cfg.logging.loglevel)
    assert cfg.logging.logfile_frontend == logfile


def test_setup_logging():
    setup_logging(ArgumentMock, 'non-default')
    logger = logging.getLogger()
    assert logger.getEffectiveLevel() == logging.NOTSET
    assert Path(ArgumentMock.log_file).exists()
