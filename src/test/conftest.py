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


class DatabaseInterfaces(NamedTuple):
    common: DbInterfaceCommon
    backend: BackendDbInterface
    frontend: FrontEndDbInterface
    frontend_editing: FrontendEditingDbInterface
    admin: AdminDbInterface
    comparison: ComparisonDbInterface
    stats_update: StatsUpdateDbInterface


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


class ConfigCommonMock(BaseModel, extra=Extra.forbid):
    """This class is a mock of :py:class:`config.Common` which only contains
    postgres and redis configuration.
    """

    postgres: config.Common.Postgres
    redis: config.Common.Redis


class MockIntercom:
    def __init__(self):
        self.deleted_files = []

    def delete_file(self, uid_list: List[str]):
        self.deleted_files.extend(uid_list)


@pytest.fixture(scope='session')
def _database_interfaces():
    """Creates the tables that backend needs.
    This is equivalent to executing ``init_postgres.py``.
    """
    # Since this fixture is session scope it cant use the function scoped fixture common_config.
    # To create the database we need the database section to be loaded.
    # We just patch it here.
    with pytest.MonkeyPatch.context() as mpk:
        config.load()
        # Make sure to match the config here with the one in src/conftest.py:common_config
        sections = {
            'postgres': {
                'server': config.common.postgres.server,
                'port': config.common.postgres.port,
                'database': config.common.postgres.test_database,
                'test-database': config.common.postgres.test_database,
                'ro-user': config.common.postgres.ro_user,
                'ro-pw': config.common.postgres.ro_pw,
                'rw-user': config.common.postgres.rw_user,
                'rw-pw': config.common.postgres.rw_pw,
                'del-user': config.common.postgres.del_user,
                'del-pw': config.common.postgres.del_pw,
                'admin-user': config.common.postgres.del_user,
                'admin-pw': config.common.postgres.del_pw,
            },
            'redis': {
                'fact-db': config.common.redis.test_db,  # Note: This is unused in testing
                'test-db': config.common.redis.test_db,  # Note: This is unused in production
                'host': config.common.redis.host,
                'port': config.common.redis.port,
            },
        }

        config._replace_hyphens_with_underscores(sections)
        common_cfg = ConfigCommonMock(**sections)

        mpk.setattr('config._common', common_cfg)

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


@pytest.fixture
def database_interfaces(_database_interfaces) -> DatabaseInterfaces:
    """Returns an object containing all database interfaces.
    The database is emptied after this fixture goes out of scope.
    """
    try:
        yield _database_interfaces
    finally:
        with _database_interfaces.admin.get_read_write_session() as session:
            # clear rows from test db between tests
            for table in reversed(_database_interfaces.admin.connection.base.metadata.sorted_tables):
                session.execute(table.delete())

        # clean intercom mock
        if hasattr(_database_interfaces.admin.intercom, 'deleted_files'):
            _database_interfaces.admin.intercom.deleted_files.clear()


@pytest.fixture
def common_db(database_interfaces) -> DbInterfaceCommon:
    """Convenience fixture. Equivalent to ``database_interfaces.common``."""
    return database_interfaces.common


@pytest.fixture
def backend_db(database_interfaces) -> BackendDbInterface:
    """Convenience fixture. Equivalent to ``database_interfaces.backend``."""
    return database_interfaces.backend


@pytest.fixture
def frontend_db(database_interfaces) -> FrontEndDbInterface:
    """Convenience fixture. Equivalent to ``database_interfaces.frontend``."""
    return database_interfaces.frontend


@pytest.fixture
def frontend_editing_db(database_interfaces) -> FrontendEditingDbInterface:
    """Convenience fixture. Equivalent to ``database_interfaces.frontend_editing``."""
    return database_interfaces.frontend_editing


@pytest.fixture
def admin_db(database_interfaces) -> AdminDbInterface:
    """Convenience fixture. Equivalent to ``database_interfaces.admin``."""
    return database_interfaces.admin


@pytest.fixture
def comparison_db(database_interfaces) -> ComparisonDbInterface:
    """Convenience fixture. Equivalent to ``database_interfaces.comparison``."""
    return database_interfaces.comparison


@pytest.fixture
def stats_update_db(database_interfaces) -> StatsUpdateDbInterface:
    """Convenience fixture. Equivalent to ``database_interfaces.stats_update``."""
    return database_interfaces.stats_update
