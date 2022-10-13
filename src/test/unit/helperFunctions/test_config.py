import logging
import os
from pathlib import Path

import pytest

from helperFunctions.config import get_config_dir, get_temp_dir_path, load_config, read_list_from_config
from test.common_helper import get_test_data_dir


def test_get_config_dir():
    assert os.path.exists(f'{get_config_dir()}/main.cfg'), 'main config file not found'


def test_load_config(monkeypatch):
    monkeypatch.setattr('helperFunctions.config.get_config_dir', lambda: f'{get_test_data_dir()}/helperFunctions')
    test_config = load_config('test.cfg')
    assert test_config['test']['test'] == 'test_config', 'config not correct'


@pytest.mark.parametrize('input_data, expected', [
    ('', []),
    ('item1', ['item1']),
    ('item1, item2, item3', ['item1', 'item2', 'item3']),
    ('item1,item2,item3', ['item1', 'item2', 'item3']),
    (' item1 , item2 , item3 ', ['item1', 'item2', 'item3']),
])
def test_read_list_from_config(monkeypatch, input_data, expected):
    monkeypatch.setattr('helperFunctions.config.get_config_dir', lambda: f'{get_test_data_dir()}/helperFunctions')
    test_config = load_config('test.cfg')
    test_config.add_section('test_section')
    test_config.set('test_section', 'test_option', input_data)
    result = read_list_from_config(test_config, 'test_section', 'test_option')
    assert result == expected


def test_read_list_from_config__key_not_in_config(monkeypatch):
    monkeypatch.setattr('helperFunctions.config.get_config_dir', lambda: f'{get_test_data_dir()}/helperFunctions')
    test_config = load_config('test.cfg')
    result = read_list_from_config(test_config, 'foo', 'bar')
    assert result == []

    result = read_list_from_config(test_config, 'test', 'bar')
    assert result == []


def test_read_list_from_config__no_config():
    result = read_list_from_config(None, 'foo', 'bar')
    assert result == []


class MockConfig:
    def __init__(self, folder: str):
        self.dir = folder

    def get(self, *_, **__):
        return self.dir


def test_get_temp_dir_path(caplog):
    assert get_temp_dir_path() == '/tmp'
    assert get_temp_dir_path(MockConfig(get_test_data_dir())) == get_test_data_dir()
    not_a_dir = str(Path(get_test_data_dir()) / '__init__.py')
    with caplog.at_level(logging.WARNING):
        assert get_temp_dir_path(MockConfig(not_a_dir)) == '/tmp'
        assert 'TempDir path does not exist and could not be created' in caplog.messages[0]
