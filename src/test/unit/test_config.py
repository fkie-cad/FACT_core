import pydantic
import pytest

# We explicitly don't want the patch_cfg fixture to be able to patch this function
from config import load
from config import cfg, configparser_cfg
from test.common_helper import get_test_data_dir


def test_load():
    cfg_path = get_test_data_dir() + '/load_cfg_test'
    load(path=cfg_path)

    assert cfg is not None, 'cfg global was not set'
    assert configparser_cfg is not None, 'configparser_cfg global was not set'


def test_load_missing_entrys():

    cfg_path = get_test_data_dir() + '/load_cfg_test_missing_entrys'

    with pytest.raises(pydantic.error_wrappers.ValidationError, match='postgres_server'):

        load(path=cfg_path)
