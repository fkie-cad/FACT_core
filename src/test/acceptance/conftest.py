# pylint: disable=no-self-use
import os
import time
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Event, Value

import pytest

from intercom.back_end_binding import InterComBackEndBinding
from scheduler.analysis import AnalysisScheduler
from scheduler.comparison_scheduler import ComparisonScheduler
from scheduler.unpacking_scheduler import UnpackingScheduler
from storage.db_interface_backend import BackendDbInterface
from storage.fsorganizer import FSOrganizer
from storage.unpacking_locks import UnpackingLockManager


class Services:
    def __init__(self, analysis_service, unpacking_service, compare_service, intercom, fs_organizer, db_backend_interface):
        # TODO 's/service/scheduler/g'
        self.analysis_service = analysis_service
        self.unpacking_service = unpacking_service
        self.compare_service = compare_service
        self.intercom = intercom
        self.fs_organizer = fs_organizer
        self.db_backend_interface = db_backend_interface


@pytest.fixture
def analysis_finished_event() -> Event:
    """An `Event` that is set once all queued firmware samples were analysed by the `AnalysisScheduler`.
    """
    return Event()


@pytest.fixture
def compare_finished_event() -> Event:
    """An `Event` that is set once all queued firmware samples were compared by the `ComparisonScheduler`.
    """
    return Event()


@pytest.fixture
def elements_finished_analyzing() -> Value:
    """A `Value` that is set to the amount of firmware samples analysed by the `AnalysisScheduler`.
    """
    return Value('i', 0)

# Look at the web_inferface fixture.
# Provide convinience fixtures for analysis_scheduler etc.
# TODO this can be deduplicated
# The problem is that we have to chose wheter or not to use the real database
# Also document the dataflow of fileobjects between unpacker, analysis, compare
# TODO scope? Starting takes a long time
@pytest.fixture
def backend_services(request, cfg_tuple, use_database, analysis_finished_event, compare_finished_event, elements_finished_analyzing) -> Services:
    """A fixture that starts the backend.
    Use the `pytest.mark.add_objects(fw1, fw2, ...)` to add objects to the database.
    See also:
        - `analysis_finished_event`
        - `compare_finished_event`
        - `elements_finished_analyzing`
    """

    _, configparser_cfg = cfg_tuple

    add_objects_marker = request.node.get_closest_marker('add_objects')
    objects = add_objects_marker.args if add_objects_marker else []

    backend_db_interface = BackendDbInterface(
        config=configparser_cfg,
    )

    for obj in objects:
        backend_db_interface.add_object(obj)

    def _analysis_callback(uid: str, plugin: str, analysis_dict: dict):
        # Store the analysis in the database (This is the default callback)
        backend_db_interface.add_analysis(uid, plugin, analysis_dict)

        elements_finished_analyzing.value += 1
        # TODO Why is the comment true, make it configurable via a mark
        # two firmware container with 3 included files each times three plugins
        if elements_finished_analyzing.value == 4 * 2 * 3:
            analysis_finished_event.set()

    def _compare_callback():
        compare_finished_event.set()

    _unpacking_locks = UnpackingLockManager()
    analysis_scheduler = AnalysisScheduler(
        config=configparser_cfg,
        post_analysis=_analysis_callback,
        unpacking_locks=_unpacking_locks,
    )
    unpacking_scheduler = UnpackingScheduler(
        config=configparser_cfg,
        # Start the analysis once unpacking finished
        post_unpack=analysis_scheduler.start_analysis_of_object,
        unpacking_locks=_unpacking_locks,
    )
    compare_scheduler = ComparisonScheduler(
        config=configparser_cfg,
        callback=_compare_callback,
    )
    intercom = InterComBackEndBinding(
        config=configparser_cfg,
        analysis_service=analysis_scheduler,
        compare_service=compare_scheduler,
        unpacking_service=unpacking_scheduler,
        unpacking_locks=_unpacking_locks,
    )
    fs_organizer = FSOrganizer(
        config=configparser_cfg,
    )

    # Wait until the backend is started
    # TODO proper startup notification
    # Removing this line does not change anything on my system?!
    time.sleep(2)
    yield Services(
        analysis_scheduler,
        unpacking_scheduler,
        compare_scheduler,
        intercom,
        fs_organizer,
        backend_db_interface
    )

    with ThreadPoolExecutor(max_workers=4) as pool:
        pool.submit(intercom.shutdown)
        pool.submit(compare_scheduler.shutdown)
        pool.submit(unpacking_scheduler.shutdown)
        pool.submit(analysis_scheduler.shutdown)


class TestFW:
    def __init__(self, uid, path, name):
        self.uid = uid
        self.path = path
        self.name = name
        self.file_name = os.path.basename(self.path)


@pytest.fixture
def test_fw_a():
    return TestFW('418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787', 'container/test.zip', 'test_fw_a')


@pytest.fixture
def test_fw_b():
    return TestFW('d38970f8c5153d1041810d0908292bc8df21e7fd88aab211a8fb96c54afe6b01_319', 'container/test.7z', 'test_fw_b')


@pytest.fixture
def test_fw_c():
    return TestFW('5fadb36c49961981f8d87cc21fc6df73a1b90aa1857621f2405d317afb994b64_68415', 'regression_one', 'test_fw_c')
