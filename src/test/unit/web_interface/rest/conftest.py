from tempfile import TemporaryDirectory

import pytest

from test.common_helper import DatabaseMock, fake_exit, get_config_for_testing
from web_interface.frontend_main import WebFrontEnd


@pytest.fixture(scope='function', autouse=True)
def mocking_the_database(monkeypatch):
    monkeypatch.setattr('helperFunctions.database.ConnectTo.__enter__', lambda _: DatabaseMock())
    monkeypatch.setattr('helperFunctions.database.ConnectTo.__exit__', fake_exit)


@pytest.fixture(scope='module')
def test_config():
    return get_config_for_testing(TemporaryDirectory())


@pytest.fixture(scope='module')
def test_app(test_config):  # pylint: disable=redefined-outer-name
    client = WebFrontEnd(config=test_config)
    return client.app.test_client()


def decode_response(response):
    return response.json
