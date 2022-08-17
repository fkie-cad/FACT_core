import logging
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from helperFunctions.program_setup import _get_console_output_level, _load_config, program_setup, setup_logging
from test.common_helper import get_test_data_dir  # pylint: disable=wrong-import-order


class ArgumentMock:

    config_file = get_test_data_dir() + '/load_cfg_test'
    log_file = '/log/file/path'
    log_level = 'DEBUG'
    silent = False
    debug = False


config_mock = {
    'logging': {
        'logfile': '/tmp/fact_test.log',
        'loglevel': 'DEBUG',
    }
}


@pytest.mark.parametrize('input_data, expected_output', [(True, logging.DEBUG), (False, logging.INFO)])
def test_get_console_output_level(input_data, expected_output):
    assert _get_console_output_level(input_data) == expected_output


def test_load_config():
    args = ArgumentMock()
    config = _load_config(args)
    assert config['logging']['loglevel'] == 'DEBUG'
    assert config['logging']['logfile'] == '/log/file/path'


def test_setup_logging():
    args = ArgumentMock
    setup_logging(config_mock, args)
    logger = logging.getLogger('')
    assert logger.getEffectiveLevel() == logging.DEBUG


def test_program_setup():
    with TemporaryDirectory(prefix='fact_test_') as tmp_dir:
        log_file_path = Path(tmp_dir) / 'folder' / 'log_file'
        options = ['script_name', '--config_file', ArgumentMock.config_file, '--log_file', str(log_file_path)]
        args, config = program_setup('test', 'test description', command_line_options=options)
        assert args.debug is False
        assert config['logging']['logfile'] == str(log_file_path)
        assert log_file_path.exists()
