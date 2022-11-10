import os

import pytest

from config import parse_comma_separated_list
from helperFunctions.config_deprecated import get_config_dir


def test_get_config_dir():
    assert os.path.exists(f'{get_config_dir()}/main.cfg'), 'main config file not found'


@pytest.mark.parametrize(
    'input_data, expected',
    [
        ('', []),
        ('item1', ['item1']),
        ('item1, item2, item3', ['item1', 'item2', 'item3']),
        ('item1,item2,item3', ['item1', 'item2', 'item3']),
        (' item1 , item2 , item3 ', ['item1', 'item2', 'item3']),
    ],
)
def test_parse_comma_separeted_list(input_data, expected):
    result = parse_comma_separated_list(input_data)
    assert result == expected


class MockConfig:
    def __init__(self, folder: str):
        self.dir = folder

    def get(self, *_, **__):
        return self.dir
