from typing import List

import pytest
from pydantic import BaseModel, Extra

import config
from storage.db_connection import ReadOnlyConnection, ReadWriteConnection
from storage.db_interface_admin import AdminDbInterface
from storage.db_interface_backend import BackendDbInterface
from storage.db_interface_common import DbInterfaceCommon
from storage.db_interface_comparison import ComparisonDbInterface
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_frontend_editing import FrontendEditingDbInterface
from storage.db_setup import DbSetup
from test.common_helper import clear_test_tables, setup_test_tables


class DB:
    def __init__(
        self,
        common: DbInterfaceCommon,
        backend: BackendDbInterface,
        frontend: FrontEndDbInterface,
        frontend_editing: FrontendEditingDbInterface,
        admin: AdminDbInterface,
    ):
        self.common = common
        self.backend = backend
        self.frontend = frontend
        self.frontend_ed = frontend_editing
        self.admin = admin


class MockConfig(BaseModel, extra=Extra.forbid):
    """This class is a mock of ``config.py:Config``.
    It must contain exactly what is needed for everything in the storage module to work.
    This can be found e.g. by using ripgrep: ``rg 'cfg\.'``.
    """

    class MockDataStorage(BaseModel, extra=Extra.forbid):
        postgres_server: str
        postgres_port: int
        postgres_database: str
        postgres_test_database: str

        postgres_ro_user: str
        postgres_ro_pw: str

        postgres_rw_user: str
        postgres_rw_pw: str

        postgres_del_user: str
        postgres_del_pw: str

        postgres_admin_user: str
        postgres_admin_pw: str

        redis_fact_db: str
        redis_test_db: str
        redis_host: str
        redis_port: int

    data_storage: MockDataStorage


# Integration tests test the system as a whole so one can reasonably expect the database to be populated.
@pytest.fixture(autouse=True, scope="session")
def _db_interface():
    """Creates the tables that backend needs.
    This is equivalent to executing ``init_postgres.py``.
    """
    # Since this fixture is session scope it cant use the function scoped fixture cfg_tuple.
    # To create the database we need the database section to be loaded.
    # We just patch it here.
    with pytest.MonkeyPatch.context() as mpk:
        config.load()
        # Make sure to match the config here with the one in src/conftest.py:_get_test_config_tuple
        sections = {
            'data-storage': {
                'postgres-server': 'localhost',
                'postgres-port': '5432',
                'postgres-database': 'fact_test',
                'postgres-test-database': 'fact_test',
                'postgres-ro-user': config.cfg.data_storage.postgres_ro_user,
                'postgres-ro-pw': config.cfg.data_storage.postgres_ro_pw,
                'postgres-rw-user': config.cfg.data_storage.postgres_rw_user,
                'postgres-rw-pw': config.cfg.data_storage.postgres_rw_pw,
                'postgres-del-user': config.cfg.data_storage.postgres_del_user,
                'postgres-del-pw': config.cfg.data_storage.postgres_del_pw,
                'postgres-admin-user': config.cfg.data_storage.postgres_del_user,
                'postgres-admin-pw': config.cfg.data_storage.postgres_del_pw,
                'redis-fact-db': config.cfg.data_storage.redis_test_db,  # Note: This is unused in testing
                'redis-test-db': config.cfg.data_storage.redis_test_db,  # Note: This is unused in production
                'redis-host': config.cfg.data_storage.redis_host,
                'redis-port': config.cfg.data_storage.redis_port,
            },
        }

        config._replace_hyphens_with_underscores(sections)
        cfg = MockConfig(**sections)

        mpk.setattr("config._cfg", cfg)

        db_setup = DbSetup()

        admin = AdminDbInterface(intercom=MockIntercom())
        ro_connection = ReadOnlyConnection()
        rw_connection = ReadWriteConnection()
        common = DbInterfaceCommon(connection=ro_connection)
        backend = BackendDbInterface(connection=rw_connection)
        frontend = FrontEndDbInterface(connection=ro_connection)
        frontend_ed = FrontendEditingDbInterface(connection=rw_connection)

    setup_test_tables(db_setup)

    yield DB(common, backend, frontend, frontend_ed, admin)

    clear_test_tables(db_setup)


@pytest.fixture(scope='function')
def db(_db_interface) -> DB:  # pylint: disable=invalid-name,redefined-outer-name
    """Returns an object containing all database intefaces.
    The database is emptied after this fixture goes out of scope.
    """
    try:
        yield _db_interface
    finally:
        with _db_interface.admin.get_read_write_session() as session:
            # clear rows from test db between tests
            for table in reversed(_db_interface.admin.connection.base.metadata.sorted_tables):
                session.execute(table.delete())
        # clean intercom mock
        if hasattr(_db_interface.admin.intercom, 'deleted_files'):
            _db_interface.admin.intercom.deleted_files.clear()


class MockIntercom:
    def __init__(self):
        self.deleted_files = []

    def delete_file(self, uid_list: List[str]):
        self.deleted_files.extend(uid_list)


@pytest.fixture()
def comp_db():
    yield ComparisonDbInterface()
