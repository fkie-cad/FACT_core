import pytest

from test.common_helper import clear_test_tables, setup_test_tables


# TODO scope, documentation
# IMO this is okay to be autoused because integration tests, test the integration of the system as a whole
# so one would expect the db to work
@pytest.fixture
def create_tables(cfg_tuple):
    _, configparser_cfg = cfg_tuple
    setup_test_tables(configparser_cfg)
    yield
    clear_test_tables(configparser_cfg)
