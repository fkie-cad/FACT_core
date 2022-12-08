import os
from pathlib import Path

import pytest

from intercom.back_end_binding import InterComBackEndBinding
from test.common_helper import get_test_data_dir
from web_interface.frontend_main import WebFrontEnd


@pytest.fixture
def web_frontend():
    _web_frontend = WebFrontEnd()
    _web_frontend.app.config['TESTING'] = True

    return _web_frontend


@pytest.fixture
def test_client(web_frontend):
    return web_frontend.app.test_client()


@pytest.fixture
def intercom_backend_binding(_unpacking_lock_manager, analysis_scheduler, comparison_scheduler, unpacking_scheduler):
    _intercom_backend_binding = InterComBackEndBinding(
        analysis_service=analysis_scheduler,
        compare_service=comparison_scheduler,
        unpacking_service=unpacking_scheduler,
        unpacking_locks=_unpacking_lock_manager,
    )
    _intercom_backend_binding.start()

    yield _intercom_backend_binding

    _intercom_backend_binding.shutdown()


class TestFW:
    def __init__(self, uid, path, name):
        self.uid = uid
        self.path = path
        self.name = name
        self.file_name = os.path.basename(self.path)


test_fw_a = TestFW(
    '418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787',
    'container/test.zip',
    'test_fw_a',
)


test_fw_b = TestFW(
    'd38970f8c5153d1041810d0908292bc8df21e7fd88aab211a8fb96c54afe6b01_319',
    'container/test.7z',
    'test_fw_b',
)


test_fw_c = TestFW(
    '5fadb36c49961981f8d87cc21fc6df73a1b90aa1857621f2405d317afb994b64_68415',
    'regression_one',
    'test_fw_c',
)


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
