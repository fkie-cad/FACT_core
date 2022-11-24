from typing import List, NamedTuple

import pytest
from pydantic import BaseModel, Extra

from scheduler.analysis import AnalysisScheduler
from scheduler.unpacking_scheduler import UnpackingScheduler
from scheduler.comparison_scheduler import ComparisonScheduler
from multiprocessing import Queue, Event

from objects.firmware import Firmware
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
def _setup_tables():
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

        # TODO is the comment correct?
        # Only the postgres database is used. Redis is mocked.
        ro_connection = ReadOnlyConnection()
        rw_connection = ReadWriteConnection()

        common = DbInterfaceCommon(connection=ro_connection)
        backend = BackendDbInterface(connection=rw_connection)
        frontend = FrontEndDbInterface(connection=ro_connection)
        frontend_editing = FrontendEditingDbInterface(connection=rw_connection)
        # TODO rw or ro ?!
        comparison = ComparisonDbInterface(connection=rw_connection)
        admin = AdminDbInterface(intercom=MockIntercom())
        stats_update = StatsUpdateDbInterface(connection=rw_connection)

    setup_test_tables(db_setup)

    yield DatabaseInterfaces(common, backend, frontend, frontend_editing, admin, comparison, stats_update)

    clear_test_tables(db_setup)


# TODO Only things with a rw connectino have to be reset
@pytest.fixture(scope='function')
def database_interfaces(_setup_tables) -> DatabaseInterfaces:  # pylint: disable=invalid-name,redefined-outer-name
    """Returns an object containing all database intefaces.
    The database is emptied after this fixture goes out of scope.
    """
    _database_interfaces = _setup_tables
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
def common_db(database_interfaces):
    """Convinience fixture. Equivalent to ``database_interfaces.common``."""
    yield database_interfaces.common


@pytest.fixture
def backend_db(database_interfaces):
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


# TODO have a look at create_test_firmware of test.common_helper
# Note that there is a difference between Firwmare and Fileobject
# What about using the underlying FileObject of a Firmware
@pytest.fixture
def insert_test_firmware(backend_db):
    """Returns a factory of firmwares.
    Firmwares creates by this factory are automatically inserted in the backend_db
    """
    # Same kwargs as Fimrware constructor
    # Does it even make sense to set these things here?
    # Not if we have to put extra logic here.
    # If we just give all kwargs to the firmware constructor this is fine.
    # Before this we do some sanitation
    #
    # As an alternative to accepting this much kwargs we could also just let the defaults be and let the user modify
    def _insert_test_firmware(**kwargs):
        # TODO
        # assert that the binary exists
        fw = Firmware()
        backend_db.insert_object(fw)
        return fw

    yield _insert_test_firmware


def make_analysis_pipeline(unpacking_scheduler: UnpackingScheduler, analysis_scheduler: AnalysisScheduler):
    """Interconnects analysis_scheduler, unpacking_scheduler and comparison_scheduler"""
    # TODO warn when overwriting defaults here
    unpacking_scheduler.post_unpack = analysis_scheduler.start_analysis_of_object

# TODO Documentation
# The idea is that every callback that is in the pipeline just puts its arguments in a queue
# This way the tests can ensure that everything went right
# Problem: You can't do len() on a queue.
# Tests need to figure out if all of their inputs were processed
#     Do they really?! Why not put a firmware in and only have a single one

# TODO what about the pre_* callbacks
# TODO what about the default post_* callbacks
@pytest.fixture
def analysis_scheduler() -> AnalysisScheduler:
    _analysis_scheduler = AnalysisScheduler()

    # test_regression_virtual_file_path.py
    pre_analysis_queue = Queue()
    _analysis_scheduler.pre_analysis = lambda fw: pre_analysis_queue.put(fw)

    # test_unpack_and_analyse.py
    post_analysis_queue = Queue()
    _analysis_scheduler.post_analysis = lambda *args: post_analysis_queue.put(args)

    yield _analysis_scheduler


@pytest.fixture
def unpacking_scheduler() -> UnpackingScheduler:
    _unpacking_scheduler = UnpackingScheduler()

    # test_unpack_only.py
    post_unpack_queue = Queue()
    _unpacking_scheduler.post_unpack = lambda fw: post_unpack_queue.put(fw)

    yield _unpacking_scheduler


def comparison_scheduler() -> ComparisonScheduler:
    _comparison_scheduler = ComparisonScheduler()

    # test_unpack_analyse_and_compare.py
    comparison_callback_event = Event()
    _comparison_scheduler.callback = lambda: comparison_callback_event.set()
    yield _comparison_scheduler
