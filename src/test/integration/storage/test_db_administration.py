# pylint: disable=redefined-outer-name,unused-argument,wrong-import-order
import pytest

from storage.db_administration import DbAdministration
from test.common_helper import get_config_for_testing


@pytest.fixture(scope='module')
def config():
    return get_config_for_testing()


@pytest.fixture(scope='module')
def admin_db(config):
    yield DbAdministration(config)


def test_user_exists(db, admin_db, config):
    admin_user = config['data_storage']['postgres_admin_user']
    assert admin_db.user_exists(admin_user)
    assert not admin_db.user_exists('foobar')


def test_db_exists(db, admin_db, config):
    db_name = config['data_storage']['postgres_database']
    assert admin_db.database_exists(db_name)
    assert not admin_db.database_exists('foobar')
