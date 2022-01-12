import pytest

from objects.file import FileObject
from storage_postgresql.db_interface_admin import AdminDbInterface
from storage_postgresql.db_interface_backend import BackendDbInterface
from storage_postgresql.db_interface_common import DbInterfaceCommon
from storage_postgresql.db_interface_comparison import ComparisonDbInterface
from storage_postgresql.db_interface_frontend import FrontEndDbInterface
from storage_postgresql.db_interface_frontend_editing import FrontendEditingDbInterface
from test.common_helper import get_config_for_testing  # pylint: disable=wrong-import-order


class DB:
    def __init__(
        self, common: DbInterfaceCommon, backend: BackendDbInterface, frontend: FrontEndDbInterface,
        frontend_editing: FrontendEditingDbInterface
    ):
        self.common = common
        self.backend = backend
        self.frontend = frontend
        self.frontend_ed = frontend_editing


@pytest.fixture(scope='package')
def db_interface():
    config = get_config_for_testing()
    common = DbInterfaceCommon(config)
    common.create_tables()
    backend = BackendDbInterface(config)
    frontend = FrontEndDbInterface(config)
    frontend_ed = FrontendEditingDbInterface(config)
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

    def delete_file(self, uid: FileObject):
        self.deleted_files.append(uid)


@pytest.fixture()
def admin_db():
    config = get_config_for_testing()
    interface = AdminDbInterface(config=config, intercom=MockIntercom())
    yield interface


@pytest.fixture()
def comp_db():
    config = get_config_for_testing()
    yield ComparisonDbInterface(config)
