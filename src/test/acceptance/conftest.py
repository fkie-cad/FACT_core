import pytest

# TODO
# Have a look at  test_regression_virtual_file_path.py::test_scheduler
from scheduler.analysis import AnalysisScheduler
from scheduler.comparison_scheduler import ComparisonScheduler
from scheduler.unpacking_scheduler import UnpackingScheduler
from storage.db_interface_backend import BackendDbInterface
from storage.unpacking_locks import UnpackingLockManager


@pytest.fixture
def analysis_scheduler():
    unpacking_lock_manager = UnpackingLockManager()
    analsyis_scheduler = AnalysisScheduler(
        unpacking_locks=unpacking_lock_manager,
    )
    yield analsyis_scheduler


@pytest.fixture
def unpacking_scheduler():
    yield UnpackingScheduler()


@pytest.fixture
def comparison_scheduler():
    yield ComparisonScheduler()


@pytest.fixture(autouse=True)
def _create_backend_pipeline(analysis_scheduler, unpacking_scheduler, comparison_scheduler):
    # This replaces base_full_start.py
    # If a marker is set the there the schedulers shall be connected (post_analyze etc.)
    pass


@pytest.fixture
def web_frontend():
    pass


@pytest.fixture
def test_client():
    pass


@pytest.fixture
def test_fw_a():
    pass


@pytest.fixture
def test_fw_b():
    pass


@pytest.fixture
def test_fw_c():
    pass
