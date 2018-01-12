from base64 import standard_b64encode
import json
import os
import time
import urllib.parse

from helperFunctions.fileSystem import get_test_data_dir
from test.acceptance.base import TestAcceptanceBase


class TestIntegrationRestCompareFirmware(TestAcceptanceBase):

    def setUp(self):
        super().setUp()
        self._start_backend()
        time.sleep(10)  # wait for systems to start

    def tearDown(self):
        self._stop_backend()
        super().tearDown()

    def _rest_upload_firmware(self, fw):
        testfile_path = os.path.join(get_test_data_dir(), fw.path)
        with open(testfile_path, 'rb') as fp:
            file_content = fp.read()
        data = {
            'binary': standard_b64encode(file_content).decode(),
            'file_name': 'test.zip',
            'device_name': 'test_device',
            'device_class': 'test_class',
            'firmware_version': '1.0',
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
        rv = self.test_client.put('/rest/compare', data=json.dumps({'uid_list': [self.test_fw_a.uid, self.test_fw_b.uid]}), follow_redirects=True)
        self.assertIn(b'Compare started', rv.data, 'could not start REST compare')

    def _rest_get_compare(self):
        rv = self.test_client.get('/rest/compare/{};{}'.format(self.test_fw_a.uid, self.test_fw_b.uid), follow_redirects=True)
        self.assertNotIn(b'Compare not found in database.', rv.data, 'compare not found in database')
        self.assertIn(
            b'"files_in_common": {"',
            rv.data, 'REST compare not successful'
        )

    def test_run_from_upload_to_show_analysis(self):
        self._rest_upload_firmware(self.test_fw_a)
        self._rest_upload_firmware(self.test_fw_b)
        time.sleep(20)  # wait for analysis to complete
        self._rest_search(self.test_fw_a)
        self._rest_search(self.test_fw_b)
        self._rest_start_compare()
        time.sleep(20)  # wait for analysis to complete
        self._rest_get_compare()
