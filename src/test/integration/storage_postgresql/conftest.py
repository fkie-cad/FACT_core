import pytest

from objects.file import FileObject
from storage_postgresql.db_interface_admin import AdminDbInterface
from storage_postgresql.db_interface_backend import BackendDbInterface
from storage_postgresql.db_interface_common import DbInterface
from storage_postgresql.db_interface_frontend import FrontEndDbInterface
from storage_postgresql.db_interface_frontend_editing import FrontendEditingDbInterface


class DB:
    def __init__(
        self, common: DbInterface, backend: BackendDbInterface, frontend: FrontEndDbInterface,
        frontend_editing: FrontendEditingDbInterface
    ):
        self.common = common
        self.backend = backend
        self.frontend = frontend
        self.frontend_ed = frontend_editing


@pytest.fixture(scope='package')
def db_interface():
    common = DbInterface(database='fact_test2')
    backend = BackendDbInterface(database='fact_test2')
    frontend = FrontEndDbInterface(database='fact_test2')
    frontend_ed = FrontendEditingDbInterface(database='fact_test2')
    yield DB(common, backend, frontend, frontend_ed)
    common.base.metadata.drop_all(common.engine)  # delete test db tables


@pytest.fixture(scope='function')
def db(db_interface):  # pylint: disable=invalid-name,redefined-outer-name
    try:
        yield db_interface
    finally:
        with db_interface.backend.get_read_write_session() as session:
            # clear rows from test db between tests
            for table in reversed(db_interface.backend.base.metadata.sorted_tables):
                session.execute(table.delete())


class MockIntercom:
    def __init__(self):
        self.deleted_files = []

    def delete_file(self, fo: FileObject):
        self.deleted_files.append(fo.uid)


@pytest.fixture()
def admin_db():
    interface = AdminDbInterface(database='fact_test2', config=None, intercom=MockIntercom())
    yield interface
