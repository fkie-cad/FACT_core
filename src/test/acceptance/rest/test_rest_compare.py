import json
import os
import time
import urllib.parse
from base64 import standard_b64encode
from multiprocessing import Event, Value

from storage.db_interface_backend import BackEndDbInterface
from test.acceptance.base import TestAcceptanceBase
from test.common_helper import get_test_data_dir


class TestRestCompareFirmware(TestAcceptanceBase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.db_backend_service = BackEndDbInterface(config=cls.config)
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

    @classmethod
    def tearDownClass(cls):
        cls.db_backend_service.shutdown()
        super().tearDownClass()

    def _analysis_callback(self, fo):
        self.db_backend_service.add_object(fo)
        self.elements_finished_analyzing.value += 1
        if self.elements_finished_analyzing.value == 4 * 2 * 3:  # two firmware container with 3 included files each times three plugins
            self.analysis_finished_event.set()

    def _compare_callback(self):
        self.compare_finished_event.set()

    def _rest_upload_firmware(self, fw):
        testfile_path = os.path.join(get_test_data_dir(), fw.path)
        with open(testfile_path, 'rb') as fp:
            file_content = fp.read()
        data = {
            'binary': standard_b64encode(file_content).decode(),
            'file_name': 'test.zip',
            'device_name': 'test_device',
            'device_part': 'full',
            'device_class': 'test_class',
            'version': '1.0',
            'vendor': 'test_vendor',
            'release_date': '01.01.1970',
            'tags': '',
            'requested_analysis_systems': ['software_components']
        }
        rv = self.test_client.put('/rest/firmware', data=json.dumps(data), follow_redirects=True)
        self.assertIn(b'"status": 0', rv.data, 'rest upload not successful')
        self.assertIn(fw.uid.encode(), rv.data, 'uid not found in REST upload reply')

    def _rest_search(self, fw):
        rv = self.test_client.get('/rest/firmware?query={}'.format(urllib.parse.quote('{"device_class": "test_class"}')), follow_redirects=True)
        self.assertIn(fw.uid.encode(), rv.data, 'test firmware not found in REST search')

    def _rest_start_compare(self):
        rv = self.test_client.put('/rest/compare', data=json.dumps({'uid_list': [self.test_fw_a.uid, self.test_fw_c.uid]}), follow_redirects=True)
        self.assertIn(b'Compare started', rv.data, 'could not start REST compare')

    def _rest_get_compare(self):
        rv = self.test_client.get('/rest/compare/{};{}'.format(self.test_fw_a.uid, self.test_fw_c.uid), follow_redirects=True)
        self.assertNotIn(b'Compare not found in database.', rv.data, 'compare not found in database')
        self.assertIn(
            b'"files_in_common": {"',
            rv.data, 'REST compare not successful'
        )

    def test_run_from_upload_to_show_analysis(self):
        self._rest_upload_firmware(self.test_fw_a)
        self._rest_upload_firmware(self.test_fw_c)
        self.analysis_finished_event.wait(timeout=20)
        self._rest_search(self.test_fw_a)
        self._rest_search(self.test_fw_c)
        self._rest_start_compare()
        self.compare_finished_event.wait(timeout=20)
        self._rest_get_compare()
