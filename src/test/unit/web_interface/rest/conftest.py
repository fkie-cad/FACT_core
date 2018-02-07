import json
from tempfile import TemporaryDirectory

import pytest

from helperFunctions.config import get_config_for_testing
from test.common_helper import DatabaseMock, fake_exit
from web_interface.frontend_main import WebFrontEnd


@pytest.fixture(scope='function', autouse=True)
def mocking_the_database(monkeypatch):
    monkeypatch.setattr('helperFunctions.web_interface.ConnectTo.__enter__', lambda _: DatabaseMock())
    monkeypatch.setattr('helperFunctions.web_interface.ConnectTo.__exit__', fake_exit)


@pytest.fixture(scope='module')
def test_config():
    return get_config_for_testing(TemporaryDirectory())


@pytest.fixture(scope='module')
def test_app(test_config):
    client = WebFrontEnd(config=test_config)
    return client.app.test_client()


def decode_response(response):
    response_bytes = response.data
    if b'Redirecting' in response_bytes:
        raise AssertionError('You seem to not be authenticated (or something else is redirecting you)')
    return json.loads(response_bytes.decode())


'''
@pytest.fixture(scope='module', autouse=True)
def login_test_user(test_app):
    if USE_AUTHENTICATION:
        token = get_token(test_app)
        test_app.post('/login', data=dict(email='test', password='test', csrf_token=token), follow_redirects=True)
        yield
        test_app.get('/logout')


def get_token(client):
    import re
    get_result = client.get('/login').data.decode()

    for line in get_result.splitlines():
        if 'csrf_token' in line:
            return re.findall(r'value="(.*)"', line)[0]
    raise RuntimeError('Unable to determine csrf_token')
'''