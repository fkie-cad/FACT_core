from typing import List

import pytest

from storage.db_connection import ReadOnlyConnection, ReadWriteConnection
from storage.db_interface_admin import AdminDbInterface
from storage.db_interface_backend import BackendDbInterface
from storage.db_interface_common import DbInterfaceCommon
from storage.db_interface_comparison import ComparisonDbInterface
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_frontend_editing import FrontendEditingDbInterface
from test.common_helper import clear_test_tables  # pylint: disable=wrong-import-order
from test.common_helper import get_config_for_testing, setup_test_tables  # pylint: disable=wrong-import-order


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


@pytest.fixture(scope='session')
def db_interface():
    config = get_config_for_testing()
    admin = AdminDbInterface(config, intercom=MockIntercom())
    setup_test_tables(config)
    ro_connection = ReadOnlyConnection(config)
    rw_connection = ReadWriteConnection(config)
    common = DbInterfaceCommon(config, connection=ro_connection)
    backend = BackendDbInterface(config, connection=rw_connection)
    frontend = FrontEndDbInterface(config, connection=ro_connection)
    frontend_ed = FrontendEditingDbInterface(config, connection=rw_connection)
    try:
        yield DB(common, backend, frontend, frontend_ed, admin)
    finally:
        clear_test_tables(config)


@pytest.fixture(scope='function')
def db(db_interface):  # pylint: disable=invalid-name,redefined-outer-name
    try:
        yield db_interface
    finally:
        with db_interface.admin.get_read_write_session() as session:
            # clear rows from test db between tests
            for table in reversed(db_interface.admin.connection.base.metadata.sorted_tables):
                session.execute(table.delete())
        # clean intercom mock
        if hasattr(db_interface.admin.intercom, 'deleted_files'):
            db_interface.admin.intercom.deleted_files.clear()


class MockIntercom:
    def __init__(self):
        self.deleted_files = []

    def delete_file(self, uid_list: List[str]):
        self.deleted_files.extend(uid_list)


@pytest.fixture()
def comp_db():
    config = get_config_for_testing()
    yield ComparisonDbInterface(config)
