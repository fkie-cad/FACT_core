# pylint: disable=wrong-import-order

import time
import urllib.parse
from base64 import standard_b64encode
from multiprocessing import Event, Value
from pathlib import Path

from storage.db_interface_backend import BackendDbInterface
from test.acceptance.base import TestAcceptanceBase
from test.common_helper import get_test_data_dir


class TestRestCompareFirmware(TestAcceptanceBase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.db_backend_service = BackendDbInterface(config=cls.config)
        cls.analysis_finished_event = Event()
        cls.compare_finished_event = Event()
        cls.elements_finished_analyzing = Value('i', 0)

    def setUp(self):
        super().setUp()
        self._start_backend(post_analysis=self._analysis_callback, compare_callback=self._compare_callback)
        time.sleep(2)  # wait for systems to start

    def tearDown(self):
        self._stop_backend()
        super().tearDown()

    def _analysis_callback(self, uid: str, plugin: str, analysis_dict: dict):
        self.db_backend_service.add_analysis(uid, plugin, analysis_dict)
        self.elements_finished_analyzing.value += 1
        if self.elements_finished_analyzing.value == 4 * 2 * 3:  # two firmware container with 3 included files each times three plugins
            self.analysis_finished_event.set()

    def _compare_callback(self):
        self.compare_finished_event.set()

    def _rest_upload_firmware(self, fw):
        testfile_path = Path(get_test_data_dir()) / fw.path
        file_content = testfile_path.read_bytes()
        data = {
            'binary': standard_b64encode(file_content).decode(),
            'file_name': 'test.zip',
            'device_name': 'test_device',
            'device_part': 'full',
            'device_class': 'test_class',
            'version': '1.0',
            'vendor': 'test_vendor',
            'release_date': '1970-01-01',
            'tags': '',
            'requested_analysis_systems': ['software_components']
        }
        rv = self.test_client.put('/rest/firmware', json=data, follow_redirects=True)
        assert b'"status": 0' in rv.data, 'rest upload not successful'
        assert fw.uid.encode() in rv.data, 'uid not found in REST upload reply'

    def _rest_search(self, fw):
        query = urllib.parse.quote('{"device_class": "test_class"}')
        rv = self.test_client.get(f'/rest/firmware?query={query}', follow_redirects=True)
        assert fw.uid.encode() in rv.data, 'test firmware not found in REST search'

    def _rest_start_compare(self):
        data = {'uid_list': [self.test_fw_a.uid, self.test_fw_c.uid]}
        rv = self.test_client.put('/rest/compare', json=data, follow_redirects=True)
        assert b'Compare started' in rv.data, 'could not start REST compare'

    def _rest_get_compare(self):
        rv = self.test_client.get(f'/rest/compare/{self.test_fw_a.uid};{self.test_fw_c.uid}', follow_redirects=True)
        assert b'Compare not found in database.' not in rv.data, 'compare not found in database'
        assert b'"files_in_common": {"' in rv.data, 'REST compare not successful'

    def test_run_from_upload_to_show_analysis(self):
        self._rest_upload_firmware(self.test_fw_a)
        self._rest_upload_firmware(self.test_fw_c)
        self.analysis_finished_event.wait(timeout=20)
        self._rest_search(self.test_fw_a)
        self._rest_search(self.test_fw_c)
        self._rest_start_compare()
        self.compare_finished_event.wait(timeout=20)
        self._rest_get_compare()
