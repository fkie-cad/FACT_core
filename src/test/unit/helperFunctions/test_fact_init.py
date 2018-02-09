import pytest
import logging

from helperFunctions.fileSystem import get_test_data_dir
from fact_init import _get_console_output_level, _load_config, _setup_logging


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
