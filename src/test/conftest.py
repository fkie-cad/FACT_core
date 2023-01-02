# pylint: disable=redefined-outer-name
import dataclasses
from typing import List, NamedTuple, Type, TypeVar

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
from storage.db_interface_stats import StatsUpdateDbInterface
from storage.db_setup import DbSetup
from test.common_helper import clear_test_tables, setup_test_tables

T = TypeVar('T')


def merge_markers(request, name: str, dtype: Type[T]) -> T:
    """Merge all markers from closest to farthest. Closer markers overwrite markers that are farther away.

    The marker must either get an instance of ``dtype`` as an argument or have one or more keyword arguments.
    The keyword arguments must be accepted by the ``dtype.__init__``.``

    :param request: The pytest request where the markers will be taken from.
    :param name: The name of the marker.
    :param dtype: The type that the marker should have. Must be a ``pydantic.dataclasses.dataclass`` or ``dict``.

    :return: An instance of ``dtype``.
    """
    _err = ValueError(
        f'The argument(s) to marker {name} must be either an instance of {dtype} or keyword arguments, not both.'
    )
    # Not well documented but iter_markers iterates from closest to farthest
    # https://docs.pytest.org/en/7.1.x/reference/reference.html?highlight=iter_markers#custom-marks
    marker_dict = {}
    for marker in reversed(list(request.node.iter_markers(name))):
        if marker.kwargs and marker.args:
            raise _err

        if marker.kwargs:
            marker_dict.update(marker.kwargs)
        elif marker.args:
            argument = marker.args[0]
            assert isinstance(argument, dtype)
            if isinstance(argument, dict):
                marker_dict.update(argument)
            else:
                marker_dict.update(dataclasses.asdict(argument))
        else:
            raise _err
    return dtype(**marker_dict)


@pytest.fixture
def create_tables():
    """Creates the tables that backend needs.
    This is equivalent to executing ``init_postgres.py``.
    """
    db_setup = DbSetup()
    setup_test_tables(db_setup)
    yield
    clear_test_tables(db_setup)


class DatabaseInterfaces(NamedTuple):
    common: DbInterfaceCommon
    backend: BackendDbInterface
    frontend: FrontEndDbInterface
    frontend_editing: FrontendEditingDbInterface
    admin: AdminDbInterface
    comparison: ComparisonDbInterface
    stats_update: StatsUpdateDbInterface


class MockConfig(BaseModel, extra=Extra.forbid):
    """This class is a mock of ``config.py:Config``.
    It must contain exactly what is needed for everything in the storage module to work.
    This can be found e.g. by using ripgrep: ``rg 'cfg\\.'``.
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


class MockIntercom:
    def __init__(self):
        self.deleted_files = []

    def delete_file(self, uid_list: List[str]):
        self.deleted_files.extend(uid_list)


# Integration tests test the system as a whole so one can reasonably expect the database to be populated.
@pytest.fixture(autouse=True, scope='session')
def _database_interfaces():
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

        mpk.setattr('config._cfg', cfg)

        db_setup = DbSetup()

        ro_connection = ReadOnlyConnection()
        rw_connection = ReadWriteConnection()

        common = DbInterfaceCommon(connection=ro_connection)
        backend = BackendDbInterface(connection=rw_connection)
        frontend = FrontEndDbInterface(connection=ro_connection)
        frontend_editing = FrontendEditingDbInterface(connection=rw_connection)
        comparison = ComparisonDbInterface(connection=rw_connection)
        admin = AdminDbInterface(intercom=MockIntercom())
        stats_update = StatsUpdateDbInterface(connection=rw_connection)

    setup_test_tables(db_setup)

    yield DatabaseInterfaces(common, backend, frontend, frontend_editing, admin, comparison, stats_update)

    clear_test_tables(db_setup)


@pytest.fixture(scope='function')
def database_interfaces(
    _database_interfaces,
) -> DatabaseInterfaces:
    """Returns an object containing all database intefaces.
    The database is emptied after this fixture goes out of scope.
    """
    try:
        yield _database_interfaces
    finally:
        # clear rows from test db between tests
        _database_interfaces.admin.connection.base.metadata.drop_all(bind=_database_interfaces.admin.connection.engine)
        _database_interfaces.admin.connection.base.metadata.create_all(bind=_database_interfaces.admin.connection.engine)
        # clean intercom mock
        if hasattr(_database_interfaces.admin.intercom, 'deleted_files'):
            _database_interfaces.admin.intercom.deleted_files.clear()


@pytest.fixture
def common_db(database_interfaces):
    """Convinience fixture. Equivalent to ``database_interfaces.common``."""
    yield database_interfaces.common


@pytest.fixture
def backend_db(database_interfaces) -> BackendDbInterface:
    """Convinience fixture. Equivalent to ``database_interfaces.backend``."""
    yield database_interfaces.backend


@pytest.fixture
def frontend_db(database_interfaces):
    """Convinience fixture. Equivalent to ``database_interfaces.frontend``."""
    yield database_interfaces.frontend


@pytest.fixture
def frontend_editing_db(database_interfaces):
    """Convinience fixture. Equivalent to ``database_interfaces.frontend_editing``."""
    yield database_interfaces.frontend_editing


@pytest.fixture
def admin_db(database_interfaces):
    """Convinience fixture. Equivalent to ``database_interfaces.admin``."""
    yield database_interfaces.admin


@pytest.fixture
def comparison_db(database_interfaces):
    """Convinience fixture. Equivalent to ``database_interfaces.comparison``."""
    yield database_interfaces.comparison


@pytest.fixture
def stats_update_db(database_interfaces):
    """Convinience fixture. Equivalent to ``database_interfaces.stats_update``."""
    yield database_interfaces.stats_update
