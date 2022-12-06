import logging
from pathlib import Path
from tempfile import TemporaryDirectory

from helperFunctions.program_setup import program_setup, set_logging_cfg_from_args, setup_logging
from test.common_helper import get_test_data_dir  # pylint: disable=wrong-import-order


class ArgumentMock:
    config_file = get_test_data_dir() + '/load_cfg_test'
    log_level = 'DEBUG'
    silent = False
    debug = False

    def __init__(self, tmp_dir):
        self.log_file = str(Path(tmp_dir, 'log/file/path'))


config_mock = {'logging': {'logfile': '/tmp/fact_test.log', 'loglevel': 'DEBUG'}}


def test_setup_logging():
    with TemporaryDirectory() as tmp_dir:
        args = ArgumentMock(tmp_dir)
        set_logging_cfg_from_args(args)
        setup_logging(args)
        logger = logging.getLogger('')
        assert logger.getEffectiveLevel() == logging.DEBUG


def test_program_setup(cfg_tuple):
    cfg, _ = cfg_tuple
    with TemporaryDirectory(prefix='fact_test_') as tmp_dir:
        log_file_path = Path(tmp_dir) / 'folder' / 'log_file'
        options = [
            'script_name',
            '--config_file',
            ArgumentMock.config_file,
            '--log_file',
            str(log_file_path),
            '--log_level',
            'DEBUG',
        ]
        args = program_setup('test', 'test description', command_line_options=options)
        assert args.debug is False
        assert cfg.logging.logfile == str(log_file_path)
        assert cfg.logging.loglevel == 'DEBUG'
        assert log_file_path.exists()
