import logging
import os
from tempfile import TemporaryDirectory

import pytest

from helperFunctions.program_setup import _get_console_output_level, _load_config, _setup_logging, program_setup
from test.common_helper import get_test_data_dir


class argument_mock():

    config_file = get_test_data_dir() + '/load_cfg_test'
    log_file = '/log/file/path'
    log_level = 'DEBUG'
    silent = False
    debug = False


config_mock = {
    'Logging': {
        'logFile': '/tmp/fact_test.log',
        'logLevel': 'DEBUG'
    }
}


@pytest.mark.parametrize('input_data, expected_output', [
    (True, logging.DEBUG),
    (False, logging.INFO)
])
def test_get_console_output_level(input_data, expected_output):
    assert _get_console_output_level(input_data) == expected_output


def test_load_config():
    args = argument_mock()
    config = _load_config(args)
    assert config['Logging']['logLevel'] == 'DEBUG'
    assert config['Logging']['logFile'] == '/log/file/path'


def test_setup_logging():
    args = argument_mock
    _setup_logging(config_mock, args)
    logger = logging.getLogger('')
    assert logger.getEffectiveLevel() == logging.DEBUG


def test_program_setup():
    tmp_dir = TemporaryDirectory(prefix='fact_test_')
    log_file_path = tmp_dir.name + '/folder/log_file'
    args, config = program_setup('test', 'test description', command_line_options=['script_name', '--config_file', argument_mock.config_file, '--log_file', log_file_path])
    assert args.debug is False
    assert config['Logging']['logFile'] == log_file_path
    assert os.path.exists(log_file_path)

    tmp_dir.cleanup()
