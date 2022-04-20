import pytest

from storage.db_interface_comparison import ComparisonDbInterface

@pytest.fixture()
def comp_db(cfg_tuple):
    _, configparser_cfg = cfg_tuple
    yield ComparisonDbInterface(configparser_cfg)
