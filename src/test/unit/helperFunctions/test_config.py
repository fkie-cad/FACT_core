import os

import pytest

from helperFunctions.fileSystem import get_test_data_dir
from helperFunctions.config import get_config_dir, load_config, read_list_from_config


def test_get_config_dir():
    assert os.path.exists('{}/main.cfg'.format(get_config_dir())), 'main config file not found'


def test_load_config(monkeypatch):
    monkeypatch.setattr('helperFunctions.config.get_config_dir', lambda: '{}/helperFunctions'.format(get_test_data_dir()))
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
    monkeypatch.setattr('helperFunctions.config.get_config_dir', lambda: '{}/helperFunctions'.format(get_test_data_dir()))
    test_config = load_config('test.cfg')
    test_config.add_section('test_section')
    test_config.set('test_section', 'test_option', input_data)
    result = read_list_from_config(test_config, 'test_section', 'test_option')
    assert result == expected


def test_read_list_from_config__key_not_in_config(monkeypatch):
    monkeypatch.setattr('helperFunctions.config.get_config_dir', lambda: '{}/helperFunctions'.format(get_test_data_dir()))
    test_config = load_config('test.cfg')
    result = read_list_from_config(test_config, 'foo', 'bar')
    assert result == []

    result = read_list_from_config(test_config, 'test', 'bar')
    assert result == []


def test_read_list_from_config__no_config(monkeypatch):
    result = read_list_from_config(None, 'foo', 'bar')
    assert result == []
