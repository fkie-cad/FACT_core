from tempfile import TemporaryDirectory

import pytest

from helperFunctions.config import load_config
from storage.mongodb_docker import get_mongodb_container, wait_until_started
from test.common_helper import get_config_for_testing


@pytest.fixture(scope="session")
def start_db(request):
    config = get_config_for_testing(TemporaryDirectory(prefix='fact_test_'))
    fact_config = load_config('main.cfg')
    config.set('data_storage', 'mongo_storage_directory', fact_config.get('data_storage', 'mongo_storage_directory'))
    db_container = get_mongodb_container(config)
    db_container.start()
    wait_until_started(db_container)

    def finalize():
        db_container.stop()
        db_container.remove()
    request.addfinalizer(finalize)
