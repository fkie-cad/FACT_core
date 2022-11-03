import pydantic
import pytest

# We explicitly don't want the patch_cfg fixture to be able to patch this function
from config import cfg, configparser_cfg, load_config
from test.common_helper import get_test_data_dir


def test_load_config():
    cfg_path = get_test_data_dir() + '/load_cfg_test'
    load_config(path=cfg_path)

    assert cfg is not None, 'cfg global was not set'
    assert configparser_cfg is not None, 'configparser_cfg global was not set'


def test_load_config_missing_entrys():

    cfg_path = get_test_data_dir() + '/load_cfg_test_missing_entrys'

    with pytest.raises(pydantic.error_wrappers.ValidationError, match='postgres_server'):

        load_config(path=cfg_path)
