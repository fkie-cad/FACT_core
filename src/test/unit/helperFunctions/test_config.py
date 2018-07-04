import os
from helperFunctions.fileSystem import get_test_data_dir
from helperFunctions.config import get_config_dir, load_config


def test_get_config_dir():
    assert os.path.exists('{}/main.cfg'.format(get_config_dir())), 'main config file not found'


def test_load_config(monkeypatch):
    monkeypatch.setattr('helperFunctions.config.get_config_dir', lambda: '{}/helperFunctions'.format(get_test_data_dir()))
    test_config = load_config('test.cfg')
    assert test_config['test']['test'] == 'test_config', 'config not correct'
