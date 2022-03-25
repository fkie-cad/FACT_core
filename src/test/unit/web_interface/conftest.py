import gc

import pytest

from test.common_helper import CommonDatabaseMock, CommonIntercomMock
from web_interface.frontend_main import WebFrontEnd
from web_interface.security.authentication import add_flask_security_to_app


class FrontendDbMock:
    def __init__(self, db_mock: CommonDatabaseMock):
        self.frontend = db_mock
        self.editing = db_mock
        self.admin = db_mock
        self.comparison = db_mock
        self.template = db_mock
        self.stats_viewer = db_mock
        self.stats_updater = db_mock


class UserDbMock:
    class session:  # pylint: disable=invalid-name
        @staticmethod
        def commit():
            pass

        @staticmethod
        def rollback():
            pass


@pytest.fixture
def web_frontend(request, monkeypatch, cfg_tuple) -> WebFrontEnd:
    _, configparser_cfg = cfg_tuple

    # TODO rename marker, find out why lambda has to be used
    db_mock_marker = request.node.get_closest_marker('db_mock')
    db_mock = db_mock_marker.args[0]() if db_mock_marker else CommonDatabaseMock
    db_mock_instance = db_mock()

    # TODO rename marker, find out why lambda has to be used
    intercom_mock_marker = request.node.get_closest_marker('intercom_mock')
    intercom_mock = intercom_mock_marker.args[0]() if intercom_mock_marker else CommonIntercomMock

    def add_security_get_mocked(app):
        add_flask_security_to_app(app)
        return UserDbMock(), db_mock_instance

    monkeypatch.setattr('web_interface.frontend_main.add_flask_security_to_app', add_security_get_mocked)

    frontend = WebFrontEnd(config=configparser_cfg, db=FrontendDbMock(db_mock_instance), intercom=intercom_mock)
    frontend.app.config['TESTING'] = True

    yield frontend
    # TODO This should not have to be done here
    # State should not be stored in class variables.
    # Otherwise tests are not isolated.
    intercom_mock.tasks = []

    gc.collect()


@pytest.fixture
def test_client(web_frontend):
    yield web_frontend.app.test_client()
