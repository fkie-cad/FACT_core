import pytest

from fact.storage.db_setup import DbSetup


@pytest.fixture
def db_setup():
    return DbSetup()


def test_user_exists(db_setup, common_config):
    admin_user = common_config.postgres.admin_user
    assert db_setup.user_exists(admin_user)
    assert not db_setup.user_exists('foobar')


def test_db_exists(db_setup, common_config):
    db_name = common_config.postgres.database
    assert db_setup.database_exists(db_name)
    assert not db_setup.database_exists('foobar')
