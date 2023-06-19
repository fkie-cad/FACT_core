# pylint: disable=redefined-outer-name
from multiprocessing import Event, Queue, Value
from typing import List, NamedTuple, Type, TypeVar

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
from storage.db_interface_view_sync import ViewUpdater
from storage.db_setup import DbSetup
from storage.fsorganizer import FSOrganizer
from storage.unpacking_locks import UnpackingLockManager
from test.common_helper import clear_test_tables, setup_test_tables
from test.integration.common import MockDbInterface as BackEndDbInterfaceMock
from test.integration.common import MockFSOrganizer as FSOrganizerMock

T = TypeVar('T')


def _assert_fixture_is_requested(request: pytest.FixtureRequest, fixture: str):
    # We cannot use request.getfixturevalue() to automatically load the fixture
    # since this might cause dependency loops.
    # What we actually need is sth like lazy loading a fixture.
    assert fixture in request.fixturenames, f'{request.fixturename} cannot be used without requiring {fixture}'


def merge_markers(request, name: str, dtype: Type[T]) -> T:
    """Merge all markers from closest to farthest. Closer markers overwrite markers that are farther away.

    The marker must either get an instance of ``dtype`` as an argument or have one or more keyword arguments.
    The keyword arguments must be accepted by the ``dtype.__init__``.``

    :param request: The pytest request where the markers will be taken from.
    :param name: The name of the marker.
    :param dtype: The type that the marker should have. Must be an instance of ``pydantic.BaseModel`` or ``dict``.

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
            elif isinstance(argument, BaseModel):
                marker_dict.update(argument.dict())
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


class MockDataStorage(BaseModel):
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

    class Config:
        extra = Extra.forbid


class ConfigCommonMock(BaseModel):
    """This class is a mock of :py:class:`config.Common` which only contains
    postgres and redis configuration.
    """

    postgres: config.Common.Postgres
    redis: config.Common.Redis

    class Config:
        extra = Extra.forbid


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


@pytest.fixture
def post_analysis_queue(request) -> Queue:
    """A Queue in which the arguments of :py:func:`AnalysisScheduler.post_analysis` are put whenever it is called."""
    _assert_fixture_is_requested(request, 'analysis_scheduler')
    return Queue()


@pytest.fixture
def pre_analysis_queue(request) -> Queue:
    """A Queue in which the arguments of :py:func:`AnalysisScheduler.pre_analysis` are put whenever it is called."""
    _assert_fixture_is_requested(request, 'analysis_scheduler')

    return Queue()


@pytest.fixture
def analysis_finished_event(request) -> Event:
    """An event that is set once the :py:func:`analysis_scheduler` has analyzed
    :py:attribute:`SchedulerTestConfig.items_to_analyze` items.

    .. note::

        :py:func:`Event.wait` does not raise an exception if the timeout was reached.

    .. seealso::

       The documentation of :py:class:`SchedulerTestConfig`."""
    _assert_fixture_is_requested(request, 'analysis_scheduler')

    return Event()


@pytest.fixture
def analysis_finished_counter() -> Value:
    """A :py:class:`Value` counting how many analyses are finished."""
    return Value('i', 0)


@pytest.fixture
def _unpacking_lock_manager() -> UnpackingLockManager:
    _manager = UnpackingLockManager()
    yield _manager
    _manager.shutdown()


@pytest.fixture(name='test_config')
def _scheduler_test_config(request) -> 'SchedulerTestConfig':
    return SchedulerTestConfig.get_instance_from_request(request)


@pytest.fixture
def analysis_scheduler(
    request,
    pre_analysis_queue,
    post_analysis_queue,
    analysis_finished_event,
    analysis_finished_counter,
    _unpacking_lock_manager,
    test_config,
) -> AnalysisScheduler:
    """Returns an instance of :py:class:`~scheduler.analysis.AnalysisScheduler`.
    The scheduler has some extra testing features. See :py:class:`SchedulerTestConfig` for the features.
    """

    with MonkeyPatch.context() as mkp:
        mkp.setattr('plugins.base.ViewUpdater', test_config.view_updater_class)
        _analysis_scheduler = AnalysisScheduler(
            pre_analysis=lambda _: None,
            post_analysis=lambda *_: None,
            unpacking_locks=_unpacking_lock_manager,
        )

    _analysis_scheduler.db_backend_service = test_config.backend_db_class()

    def _pre_analysis_hook(fw):
        pre_analysis_queue.put(fw)
        if test_config.pipeline:
            _analysis_scheduler.db_backend_service.add_object(fw)

    _analysis_scheduler.pre_analysis = _pre_analysis_hook

    def _post_analysis_hook(*args):
        post_analysis_queue.put(args)
        analysis_finished_counter.value += 1
        # We use == here instead of >= to not set the thing when items_to_analyze is 0
        if analysis_finished_counter.value == test_config.items_to_analyze:
            analysis_finished_event.set()

        if test_config.pipeline:
            _analysis_scheduler.db_backend_service.add_analysis(*args)

    _analysis_scheduler.post_analysis = _post_analysis_hook

    if test_config.start_processes:
        _analysis_scheduler.start()

    yield _analysis_scheduler

    # Even if plugins are not started their constructors start a manager
    # FIXME this should only be called if test_config.start_processes is set
    _analysis_scheduler.shutdown()


@pytest.fixture
def post_unpack_queue(request) -> Queue:
    """A queue that is filled with the arguments of post_unpack of the unpacker"""
    _assert_fixture_is_requested(request, 'unpacking_scheduler')
    return Queue()


@pytest.fixture
def unpacking_scheduler(request, post_unpack_queue, _unpacking_lock_manager, test_config) -> UnpackingScheduler:
    """Returns an instance of :py:class:`~scheduler.unpacking_scheduler.UnpackingScheduler`.
    The scheduler has some extra testing features. See :py:class:`SchedulerTestConfig` for the features.
    """
    if test_config.pipeline:
        _analysis_scheduler = request.getfixturevalue('analysis_scheduler')

    _unpacking_scheduler = UnpackingScheduler(
        post_unpack=lambda _: None,
        fs_organizer=None,
        unpacking_locks=_unpacking_lock_manager,
    )

    _unpacking_scheduler.unpacker.file_storage_system = test_config.fs_organizer_class()

    def _post_unpack_hook(fw):
        post_unpack_queue.put(fw)
        if test_config.pipeline:
            _analysis_scheduler.start_analysis_of_object(fw)

    _unpacking_scheduler.post_unpack = _post_unpack_hook

    if test_config.start_processes:
        _unpacking_scheduler.start()

    yield _unpacking_scheduler

    if test_config.start_processes:
        _unpacking_scheduler.shutdown()


@pytest.fixture
def comparison_finished_event(request) -> Event:
    """The returned event is set once the comparison_scheduler is finished comparing.
    Note that the event must be reset if you want to do multiple comparisons in one test.

    .. note::

        :py:func:`Event.wait` does not raise an exception if the timeout was reached.
    """
    _assert_fixture_is_requested(request, 'comparison_scheduler')
    return Event()


@pytest.fixture
def comparison_scheduler(request, comparison_finished_event, test_config) -> ComparisonScheduler:
    """Returns an instance of :py:class:`~scheduler.comparison_scheduler.ComparisonScheduler`.
    The scheduler has some extra testing features. See :py:class:`SchedulerTestConfig` for the features.
    """
    _comparison_scheduler = ComparisonScheduler()

    _comparison_scheduler.db_interface = test_config.comparison_db_class()

    def _callback_hook():
        comparison_finished_event.set()

    _comparison_scheduler.callback = _callback_hook

    if test_config.start_processes:
        _comparison_scheduler.start()

    yield _comparison_scheduler

    if test_config.start_processes:
        _comparison_scheduler.shutdown()


class ViewUpdaterMock:
    def update_view(self, *_):
        pass


class SchedulerTestConfig(BaseModel):
    """A declarative class that describes the desired behavior for the fixtures :py:func:`~analysis_finished_event`,
     :py:func:`unpacking_scheduler` and :py:func:`comparison_scheduler`.

    The fixtures don't do any assertions, they MUST be done by the test using the fixtures.
    """

    #: The number of items that the :py:class:`~scheduler.analysis.AnalysisScheduler` must analyze before
    #: :py:func:`analysis_finished_event` gets set.
    items_to_analyze: int
    #: Set the class that is used as :py:class:`~storage.db_interface_backend.BackendDbInterface`.
    #: This can be either a mocked class or the actual :py:class:`~storage.db_interface_backend.BackendDbInterface`.
    #: This is used by the :py:func:`analysis_scheduler`
    backend_db_class: Type
    #: Set the class that is used as :py:class:`~storage.db_interface_comparison.ComparisonDbInterface`.
    #: This can be either a mocked class or the actual :py:class:`~storage.db_interface_comparison.ComparisonDbInterface`.
    #: This is used by the :py:func:`comparison_scheduler`
    comparison_db_class: Type
    #: Set the class that is used as :py:class:`~storage.fsorganizer.FSOrganizer`.
    #: This can be either a mocked class or the actual :py:class:`~storage.fsorganizer.FSOrganizer`.
    #: This is used by the :py:func:`unpacking_scheduler`
    fs_organizer_class: Type
    #: Set the class that is used as :py:class:`~storage.db_interface_view_sync.ViewUpdater`.
    #: If you set this to the actual :py:class:`~storage.db_interface_view_sync.ViewUpdater` note that the fixture
    #: :py:func:`~test.conftest.database_interfaces` has to be executed before (e.g. by
    #: ``pytest.fixture(autouse=True)``) any of the scheduler fixtures.
    view_updater_class: Type
    #: If set to ``True`` the :py:func:`unpacking_scheduler` and :py:func:`analysis_scheduler` are connected via their
    #: hooks.
    #: To be precise the analysis is started after unpacking.
    #: Also the objects to be analysed and the finished analysis is added to the backend database.
    pipeline: bool
    #: If set to ``False`` no processes will be started.
    start_processes: bool

    @staticmethod
    def Integration(**kwargs):
        return SchedulerTestConfig(
            **dict(
                {
                    'items_to_analyze': 0,
                    'backend_db_class': BackendDbInterface,
                    'comparison_db_class': ComparisonDbInterface,
                    'fs_organizer_class': FSOrganizerMock,
                    'view_updater_class': ViewUpdater,
                    'pipeline': False,
                    'start_processes': True,
                },
                **kwargs,
            )
        )

    @staticmethod
    def Unit(**kwargs):
        return SchedulerTestConfig(
            **dict(
                {
                    'items_to_analyze': 0,
                    'backend_db_class': BackEndDbInterfaceMock,
                    'comparison_db_class': ComparisonDbInterface,
                    'fs_organizer_class': FSOrganizerMock,
                    'view_updater_class': ViewUpdaterMock,
                    'pipeline': False,
                    'start_processes': False,
                },
                **kwargs,
            )
        )

    @staticmethod
    def Acceptance(**kwargs):
        return SchedulerTestConfig(
            **dict(
                {
                    'items_to_analyze': 0,
                    'backend_db_class': BackendDbInterface,
                    'comparison_db_class': ComparisonDbInterface,
                    'fs_organizer_class': FSOrganizer,
                    'view_updater_class': ViewUpdaterMock,
                    'pipeline': True,
                    'start_processes': True,
                },
                **kwargs,
            )
        )

    @staticmethod
    def get_instance_from_request(request: pytest.FixtureRequest) -> 'SchedulerTestConfig':
        err = ValueError(f'{request.module} is neither a unit, acceptance nor integration test')

        test_config_dict = merge_markers(request, 'SchedulerTestConfig', dict)

        modules = request.module.__name__.split('.')
        if len(modules) < 2:
            raise err
        test_type = modules[1]

        if test_type == 'unit':
            return SchedulerTestConfig.Unit(**test_config_dict)
        elif test_type == 'acceptance':
            return SchedulerTestConfig.Acceptance(**test_config_dict)
        elif test_type == 'integration':
            return SchedulerTestConfig.Integration(**test_config_dict)
        else:
            raise err


@pytest.fixture
def fsorganizer() -> FSOrganizer:
    return FSOrganizer()
