# pylint: disable=no-self-use
# pylint: disable=redefined-outer-name,unused-argument,wrong-import-order
import pytest

from storage.db_setup import DbSetup


# TODO scope='module'
@pytest.fixture
def db_setup(cfg_tuple):
    _, configparser_cfg = cfg_tuple
    yield DbSetup(configparser_cfg)


@pytest.mark.usefixtures('use_database')
class TestDbSetup:
    def test_user_exists(self, db_setup, cfg_tuple):
        cfg, _ = cfg_tuple
        admin_user = cfg.data_storage.postgres_admin_user
        assert db_setup.user_exists(admin_user)
        assert not db_setup.user_exists('foobar')

    def test_db_exists(self, db_setup, cfg_tuple):
        cfg, _ = cfg_tuple
        db_name = cfg.data_storage.postgres_database
        assert db_setup.database_exists(db_name)
        assert not db_setup.database_exists('foobar')
