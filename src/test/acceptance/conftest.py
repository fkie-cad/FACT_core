import pytest

from dataclasses import dataclass
from test.conftest import SchedulerTestConfig

# TODO
# Have a look at  test_regression_virtual_file_path.py::test_scheduler
from storage.db_interface_backend import BackendDbInterface
from storage.unpacking_locks import UnpackingLockManager
from storage.fsorganizer import FSOrganizer
from intercom.back_end_binding import InterComBackEndBinding
from web_interface.frontend_main import WebFrontEnd
from pathlib import Path
from test.common_helper import get_test_data_dir
import os


@pytest.fixture
def web_frontend():
    _web_frontend = WebFrontEnd()
    _web_frontend.app.config["TESTING"] = True

    yield _web_frontend


@pytest.fixture
def test_client(web_frontend):
    return web_frontend.app.test_client()


# TODO scoping: The performance loss here is really bad
@pytest.fixture
def intercom_backend_binding(request):
    # We don't want to apply (i.e. overwrite) the marker if it already exists
    if request.node.get_closest_marker("SchedulerTestConfig") is None:
        request.applymarker(pytest.mark.SchedulerTestConfig(SchedulerAcceptanceTestConfig()))
    # We had to apply the marker here first and then dynamically get the fixtures.
    # If we didn't do this the marker would not be set and the defaults would be used.
    analysis_scheduler = request.getfixturevalue("analysis_scheduler")
    comparison_scheduler = request.getfixturevalue("comparison_scheduler")
    unpacking_scheduler = request.getfixturevalue("unpacking_scheduler")

    # TODO Must this be the same as in analysis_scheduler etc?
    unpacking_locks = UnpackingLockManager()

    _intercom_backend_binding = InterComBackEndBinding(
        analysis_service=analysis_scheduler,
        compare_service=comparison_scheduler,
        unpacking_service=unpacking_scheduler,
        unpacking_locks=unpacking_locks,
    )

    yield _intercom_backend_binding

    _intercom_backend_binding.shutdown()


@dataclass
class SchedulerAcceptanceTestConfig(SchedulerTestConfig):
    """A child class of ``SchedulerTestConfig`` with the defaults tuned for acceptance tests.
    For documentation of the fields see ``SchedulerTestConfig``.
    """

    start_processes: bool = True
    pipeline: bool = True
    fs_organizer_class = FSOrganizer
    backend_db_class = BackendDbInterface
    # TODO add a toggle that states whether or not to start the full intercom_backend_binding (see fixture)


# TODO this should not exist and be replaced by Firmware
class TestFW:
    def __init__(self, uid, path, name):
        self.uid = uid
        self.path = path
        self.name = name
        self.file_name = os.path.basename(self.path)


# TODO these should be replaced by a factory or something.
# The factory must be deterministic!
# If we dont use a factory the fixtures should at least have good names describing the content of the firmware
# The doc comment should describe what one would expect from the firmware and why to use it for testing
@pytest.fixture
def test_fw_a():
    yield TestFW(
        '418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787',
        'container/test.zip',
        'test_fw_a',
    )


@pytest.fixture
def test_fw_b():
    yield TestFW(
        'd38970f8c5153d1041810d0908292bc8df21e7fd88aab211a8fb96c54afe6b01_319',
        'container/test.7z',
        'test_fw_b',
    )


@pytest.fixture
def test_fw_c():
    yield TestFW(
        '5fadb36c49961981f8d87cc21fc6df73a1b90aa1857621f2405d317afb994b64_68415',
        'regression_one',
        'test_fw_c',
    )


# TODO this should be replaced by sth more sophisticated
def upload_test_firmware(test_client, test_fw):
    testfile_path = Path(get_test_data_dir()) / test_fw.path
    with open(str(testfile_path), 'rb') as fp:
        data = {
            'file': (fp, test_fw.file_name),
            'device_name': test_fw.name,
            'device_part': 'test_part',
            'device_class': 'test_class',
            'version': '1.0',
            'vendor': 'test_vendor',
            'release_date': '1970-01-01',
            'tags': '',
            'analysis_systems': [],
        }
        rv = test_client.post('/upload', content_type='multipart/form-data', data=data, follow_redirects=True)

    assert b'Upload Successful' in rv.data, 'upload not successful'
    assert test_fw.uid.encode() in rv.data, 'uid not found on upload success page'
