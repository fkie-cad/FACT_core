# pylint: disable=redefined-outer-name,unused-argument,wrong-import-order
import pytest

from storage.db_setup import DbSetup


# TODO scope with config
# @pytest.fixture(scope='module')
@pytest.fixture
def db_setup():
    yield DbSetup()


def test_user_exists(db, db_setup, cfg_tuple):
    cfg, _ = cfg_tuple
    admin_user = cfg.data_storage.postgres_admin_user
    assert db_setup.user_exists(admin_user)
    assert not db_setup.user_exists('foobar')


def test_db_exists(db, db_setup, cfg_tuple):
    cfg, _ = cfg_tuple
    db_name = cfg.data_storage.postgres_database
    assert db_setup.database_exists(db_name)
    assert not db_setup.database_exists('foobar')
