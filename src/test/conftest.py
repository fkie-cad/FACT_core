from dataclasses import dataclass
from multiprocessing import Event, Queue, Value
from typing import List, NamedTuple, TypeVar

import pytest
from pydantic import BaseModel, Extra
from pytest import MonkeyPatch

import config
from scheduler.analysis import AnalysisScheduler
from scheduler.comparison_scheduler import ComparisonScheduler
from scheduler.unpacking_scheduler import UnpackingScheduler
from storage.db_connection import ReadOnlyConnection, ReadWriteConnection
from storage.db_interface_admin import AdminDbInterface
from storage.db_interface_backend import BackendDbInterface
from storage.db_interface_common import DbInterfaceCommon
from storage.db_interface_comparison import ComparisonDbInterface
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_frontend_editing import FrontendEditingDbInterface
from storage.db_interface_stats import StatsUpdateDbInterface
from storage.db_setup import DbSetup
from storage.unpacking_locks import UnpackingLockManager
from test.common_helper import clear_test_tables, setup_test_tables
from test.integration.common import MockDbInterface as BackEndDbInterfaceMock
from test.integration.common import MockFSOrganizer as FSOrganizerMock


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
def database_interfaces(
    _database_interfaces,
) -> DatabaseInterfaces:  # pylint: disable=invalid-name,redefined-outer-name
    """Returns an object containing all database intefaces.
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


@pytest.fixture
def post_analysis_queue():
    yield Queue()


@pytest.fixture
def pre_analysis_queue():
    yield Queue()


@pytest.fixture
def analysis_finished_event():
    """See also documentation of SchedulerTestConfig."""
    yield Event()


# TODO Documentation
# The idea is that every callback that is in the pipeline just puts its arguments in a queue
# This way the tests can ensure that everything went right
# Problem: You can't do len() on a queue.
# Tests need to figure out if all of their inputs were processed
#     Do they really?! Why not put a firmware in and only have a single one

# TODO what about the pre_* callbacks
# TODO what about the default post_* callbacks
# TODO if test_config.pipeline is true: Do we really want this?! How do we change the behavior?
# TODO what about funtions like _make_pipeline(analysis_scheduler, ...)??
# TODO what about functions like _get_test_config_for(some_scheduler)
@pytest.fixture
def analysis_scheduler(
    request,
    pre_analysis_queue,
    post_analysis_queue,
    analysis_finished_event,
) -> AnalysisScheduler:
    """Returns an analysis_scheduler.
    The scheduler has some extra testing features. See SchedulerTestConfig for the features.
    """
    # TODO merge scopes like the config mock does
    scheduler_test_config_marker = request.node.get_closest_marker('SchedulerTestConfig')
    test_config: SchedulerTestConfig = (
        scheduler_test_config_marker.args[0] if scheduler_test_config_marker else SchedulerTestConfig()
    )

    # Instanciate an AnalysisScheduler and set everything to None
    # TODO comment why we need monkeypatch here.
    # Theoretically we could also do the instanciation last but I dont like this.
    with MonkeyPatch.context() as mkp:
        mkp.setattr(AnalysisScheduler, '_start_runner_process', lambda _: None)
        mkp.setattr(AnalysisScheduler, '_start_result_collector', lambda _: None)
        _analysis_scheduler = AnalysisScheduler(
            pre_analysis=lambda _: None,
            post_analysis=lambda *_: None,
            unpacking_locks=UnpackingLockManager(),
        )

    _analysis_scheduler.db_backend_service = test_config.backend_db_class()

    # test_regression_virtual_file_path.py
    def _pre_analysis_hook(fw):
        pre_analysis_queue.put(fw)
        if test_config.pipeline:
            _analysis_scheduler.db_backend_service.add_object(fw)

    _analysis_scheduler.pre_analysis = _pre_analysis_hook

    # TODO better name
    analysis_finished_counter = Value('i', 0)

    def _post_analysis_hook(*args):
        post_analysis_queue.put(args)
        # TODO this is not atomic but matches the previous behavior
        analysis_finished_counter.value += 1
        # We use == here insead of >= to not set the thing when items_to_analyze is 0
        if analysis_finished_counter.value == test_config.items_to_analyze:
            analysis_finished_event.set()

        if test_config.pipeline:
            _analysis_scheduler.db_backend_service.add_analysis(*args)

    # test_unpack_and_analyse.py
    _analysis_scheduler.post_analysis = _post_analysis_hook

    # TODO I really hate that python does not have a defer statement
    if test_config.start_processes:
        _analysis_scheduler._start_runner_process()
        _analysis_scheduler._start_result_collector()

    yield _analysis_scheduler
    # TODO scope: Maybe get inspired by the database_interface fixture.
    # Have a module scoped thing, then have a function scoped thing that makes sure that all queues are reset.

    if test_config.start_processes:
        _analysis_scheduler.shutdown()


@pytest.fixture
def post_unpack_queue() -> Queue:
    """A queue that is filled with the arguments of post_unpack of the unpacker"""
    yield Queue()


@pytest.fixture
def unpacking_scheduler(request, post_unpack_queue) -> UnpackingScheduler:
    scheduler_test_config_marker = request.node.get_closest_marker('SchedulerTestConfig')
    test_config: SchedulerTestConfig = (
        scheduler_test_config_marker.args[0] if scheduler_test_config_marker else SchedulerTestConfig()
    )
    # TODO don't do this everytime
    # TODO only allow this if it is in request.fixturenames
    _analysis_scheduler = request.getfixturevalue('analysis_scheduler')

    with MonkeyPatch.context() as mkp:
        # self.start_unpack_workers()
        # self.work_load_process = self.start_work_load_monitor()
        mkp.setattr(UnpackingScheduler, 'start_unpack_workers', lambda _: None)
        mkp.setattr(UnpackingScheduler, 'start_work_load_monitor', lambda _: None)
        _unpacking_scheduler = UnpackingScheduler(
            post_unpack=lambda _: None,
            fs_organizer=None,
            # TODO must this be the same as in analysis_scheduler?
            unpacking_locks=UnpackingLockManager(),
        )

    _unpacking_scheduler.fs_organizer = test_config.fs_organizer_class()

    # test_unpack_only.py
    def _post_unpack_hook(fw):
        post_unpack_queue.put(fw)
        if test_config.pipeline:
            _analysis_scheduler.start_analysis_of_object(fw)

    # TODO document that the this thing is not the default one as it does not have a default
    _unpacking_scheduler.post_unpack = _post_unpack_hook

    if test_config.start_processes:
        _unpacking_scheduler.start_unpack_workers()
        _unpacking_scheduler.work_load_process = _unpacking_scheduler.start_work_load_monitor()

    yield _unpacking_scheduler

    if test_config.start_processes:
        _unpacking_scheduler.shutdown()


@pytest.fixture
def comparsion_finished_event() -> Event:
    """The retunred event is set once the comparsion_scheduler is finished comparing.
    Note that the event must be reset if you want to compare multiple firmwares in one test.
    """
    yield Event()


@pytest.fixture
def comparison_scheduler(request, comparsion_finished_event) -> ComparisonScheduler:
    scheduler_test_config_marker = request.node.get_closest_marker('SchedulerTestConfig')
    # TODO how to decide if the test is an acceptance test or an integration test
    # We could probably look at request.module to find this out
    test_config: SchedulerTestConfig = (
        scheduler_test_config_marker.args[0] if scheduler_test_config_marker else SchedulerTestConfig()
    )
    with MonkeyPatch.context() as mkp:
        mkp.setattr(ComparisonScheduler, 'start', lambda _: None)
        _comparison_scheduler = ComparisonScheduler()

    # test_unpack_analyse_and_compare.py
    def _callback_hook():
        comparsion_finished_event.set()

    _comparison_scheduler.callback = _callback_hook

    if test_config.start_processes:
        _comparison_scheduler.start()

    yield _comparison_scheduler

    if test_config.start_processes:
        _comparison_scheduler.shutdown()


# TODO remove mock from name as they can also be the real thing
BackendDbInterfaceMockClass = TypeVar('T')
FSOrganizerClass = TypeVar('T')


# TODO make sure that fixtures only use the fields intendet for them
# TODO reconsider the name
@dataclass
class SchedulerTestConfig:
    """A declarative class that describes the desired behavior for the fixtures TODO.
    All fields have a default.
    The defaults are chosen in a way that the most "default" integration test should not have to change anything.
    The notion "most default" is not defined and the defaults should be changed to reflect what the testbase is doing.

    The fixtures don't do any assertions, they MUST be done by the test using the fixtures.
    """

    # The amount of items (TODO what is an item?) that the ``AnalysisScheduler`` shall analyze in this test.
    items_to_analyze: int = 0
    # The class that shall be used as ``BackendDbInterface``.
    # This can be either a Mock or the real thing.
    # TODO is this really needed?!
    # TODO I really prefer uppercase names for Types
    backend_db_class: BackendDbInterfaceMockClass = BackEndDbInterfaceMock
    # TODO documentation
    # TODO same as backend_db_class
    fs_organizer_class: FSOrganizerClass = FSOrganizerMock
    # Interconnects the UnpackingScheduler, AnalysisScheduler and ComparisonScheduler
    # TODO document&implement this: Only interconnect the fixtures actually used by the test
    # TODO only AnalysisScheduler and UnpackingScheduler are connected
    # The comparison scheduler is NOT part of the pipeline.
    pipeline: bool = False
    # If false the respective processes will be started
    start_processes: bool = True

    @staticmethod
    def _get_from_request(request: pytest.FixtureRequest):
        pass
