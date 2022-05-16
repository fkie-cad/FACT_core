# pylint: disable=redefined-outer-name,unused-argument,wrong-import-order
import pytest

from storage.db_setup import DbSetup
from test.common_helper import get_config_for_testing


@pytest.fixture(scope='module')
def config():
    return get_config_for_testing()


@pytest.fixture(scope='module')
def db_setup(config):
    yield DbSetup(config)


def test_user_exists(db, db_setup, config):
    admin_user = config['data-storage']['postgres-admin-user']
    assert db_setup.user_exists(admin_user)
    assert not db_setup.user_exists('foobar')


def test_db_exists(db, db_setup, config):
    db_name = config['data-storage']['postgres-database']
    assert db_setup.database_exists(db_name)
    assert not db_setup.database_exists('foobar')
