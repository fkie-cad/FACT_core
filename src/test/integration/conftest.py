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
    _setup_test_tables(config, admin)
    common = DbInterfaceCommon(config)
    backend = BackendDbInterface(config)
    frontend = FrontEndDbInterface(config)
    frontend_ed = FrontendEditingDbInterface(config)
    yield DB(common, backend, frontend, frontend_ed, admin)
    admin.base.metadata.drop_all(admin.engine)  # delete test db tables


def _setup_test_tables(config, admin_interface: AdminDbInterface):
    admin_interface.create_tables()
    ro_user = config['data_storage']['postgres_ro_user']
    rw_user = config['data_storage']['postgres_rw_user']
    admin_user = config['data_storage']['postgres_admin_user']
    with admin_interface.get_read_write_session() as session:
        session.execute(f'GRANT SELECT ON ALL TABLES IN SCHEMA public TO {ro_user}')
        session.execute(f'GRANT SELECT ON ALL TABLES IN SCHEMA public TO {rw_user}')
        session.execute(f'GRANT INSERT ON ALL TABLES IN SCHEMA public TO {rw_user}')
        session.execute(f'GRANT UPDATE ON ALL TABLES IN SCHEMA public TO {rw_user}')
        session.execute(f'GRANT ALL ON ALL TABLES IN SCHEMA public TO {admin_user}')


@pytest.fixture(scope='function')
def db(db_interface):  # pylint: disable=invalid-name,redefined-outer-name
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

    def delete_file(self, uid: FileObject):
        self.deleted_files.append(uid)


@pytest.fixture()
def comp_db():
    config = get_config_for_testing()
    yield ComparisonDbInterface(config)
