import gc
from typing import List

import pytest

from storage.db_interface_admin import AdminDbInterface
from storage.db_interface_backend import BackendDbInterface
from storage.db_interface_common import DbInterfaceCommon
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_frontend_editing import FrontendEditingDbInterface
from storage.db_setup import DbSetup
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
    db_mock_marker = request.node.get_closest_marker('db_mock')
    intercom_mock_marker = request.node.get_closest_marker('intercom_mock')

    if 'test_real_database' not in request.fixturenames:
        # TODO rename marker, find out why lambda has to be used
        db_mock = db_mock_marker.args[0]() if db_mock_marker else CommonDatabaseMock
        db_mock_instance = db_mock()

        # TODO rename marker, find out why lambda has to be used
        intercom_mock = intercom_mock_marker.args[0]() if intercom_mock_marker else CommonIntercomMock

        def add_security_get_mocked(app):
            add_flask_security_to_app(app)
            return UserDbMock(), db_mock_instance

        monkeypatch.setattr('web_interface.frontend_main.add_flask_security_to_app', add_security_get_mocked)

        frontend = WebFrontEnd(config=configparser_cfg, db=FrontendDbMock(db_mock_instance), intercom=intercom_mock)
    else:
        assert db_mock_marker is None, "You can't mock the database if you use test_real_database"
        assert intercom_mock_marker is None, "You can't mock the database if you use test_real_database"

        frontend = WebFrontEnd(config=configparser_cfg)

    frontend.app.config['TESTING'] = True

    yield frontend

    if 'test_real_database' not in request.fixturenames:
        # TODO This should not have to be done here
        # State should not be stored in class variables.
        # Otherwise tests are not isolated.
        intercom_mock.tasks = []

    gc.collect()


@pytest.fixture
def test_client(web_frontend):
    yield web_frontend.app.test_client()


# TODO scope session
@pytest.fixture
def test_real_database(cfg_tuple):
    # Keep function name in sync with web_frontend fixture
    # TODO name
    _, configparser_cfg = cfg_tuple
    db_setup = DbSetup(configparser_cfg)
    db_setup.create_tables()
    db_setup.set_table_privileges()

    yield

    db_setup.base.metadata.drop_all(db_setup.engine)


# See test/integration/conftest.py
# TODO scope=function
# TODO scope=session
@pytest.fixture
def real_database(cfg_tuple, test_real_database):
    _, configparser_cfg = cfg_tuple
    admin = AdminDbInterface(configparser_cfg, intercom=MockIntercom())
    common = DbInterfaceCommon(configparser_cfg)
    backend = BackendDbInterface(configparser_cfg)
    frontend = FrontEndDbInterface(configparser_cfg)
    frontend_ed = FrontendEditingDbInterface(configparser_cfg)

    db_interface = DB(common, backend, frontend, frontend_ed, admin)

    try:
        yield db_interface
    finally:
        with db_interface.admin.get_read_write_session() as session:
            # clear rows from test db between tests
            for table in reversed(db_interface.admin.base.metadata.sorted_tables):
                session.execute(table.delete())
        # clean intercom mock
        if hasattr(db_interface.admin.intercom, 'deleted_files'):
            db_interface.admin.intercom.deleted_files.clear()


class MockIntercom:
    def __init__(self):
        self.deleted_files = []

    def delete_file(self, uid_list: List[str]):
        self.deleted_files.extend(uid_list)


class DB:
    def __init__(
        self, common: DbInterfaceCommon, backend: BackendDbInterface, frontend: FrontEndDbInterface,
        frontend_editing: FrontendEditingDbInterface, admin: AdminDbInterface
    ):
        self.common = common
        self.backend = backend
        self.frontend = frontend
        self.frontend_ed = frontend_editing
        self.admin = admin
