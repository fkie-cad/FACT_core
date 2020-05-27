# pylint:disable=attribute-defined-outside-init,redefined-outer-name,unused-argument

from contextlib import suppress
from tempfile import TemporaryDirectory

import pytest
from docker.errors import DockerException

from helperFunctions.config import load_config
from storage.mongodb_docker import container_is_running, get_mongodb_container
from test.common_helper import get_config_for_testing


@pytest.fixture(scope="session")
def start_db(request):
    config = _get_config()
    db_container = get_mongodb_container(config)
    db_container.start()

    def stop_db():
        with suppress(DockerException):
            db_container.stop()
            db_container.wait(timeout=10)
            db_container.remove()
    request.addfinalizer(stop_db)


@pytest.fixture(scope="module")
def use_db(start_db):
    config = _get_config()
    db_container = get_mongodb_container(config)
    if not container_is_running(db_container):
        db_container.start()
        assert container_is_running(db_container), 'could not restart db container'


def _get_config():
    config = get_config_for_testing(TemporaryDirectory(prefix='fact_test_'))
    fact_config = load_config('main.cfg')
    config.set('data_storage', 'mongo_storage_directory', fact_config.get('data_storage', 'mongo_storage_directory'))
    config.set('Logging', 'mongoDbLogPath', fact_config.get('Logging', 'mongoDbLogPath'))
    return config
