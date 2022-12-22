import pydantic
import pytest

# We explicitly don't want the patch_cfg fixture to be able to patch this function
# This is why we import it here
from config import load
from config import cfg, configparser_cfg, parse_comma_separated_list
from test.common_helper import get_test_data_dir


def test_load():
    cfg_path = get_test_data_dir() + '/load_cfg_test'
    load(path=cfg_path)

    assert cfg is not None, 'cfg global was not set'
    assert configparser_cfg is not None, 'configparser_cfg global was not set'
    assert cfg.data_storage.temp_dir_path == '/tmp', 'default value did not get set'
    assert getattr(cfg, 'users_and_passwords')['mime_whitelist'] == ['foo', 'bar']
    assert getattr(cfg, 'users_and_passwords')['mime_blacklist'] == ['foobar']


def test_load_missing_entrys():

    cfg_path = get_test_data_dir() + '/load_cfg_test_missing_entrys'

    with pytest.raises(pydantic.error_wrappers.ValidationError, match='postgres_server'):

        load(path=cfg_path)


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
