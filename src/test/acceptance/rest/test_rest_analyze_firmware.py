import os
import time
import json
import urllib.parse

from base64 import standard_b64encode

from test.acceptance.base import TestAcceptanceBase
from helperFunctions.fileSystem import get_test_data_dir


class TestRestFirmware(TestAcceptanceBase):

    def setUp(self):
        super().setUp()
        self._start_backend()
        self.test_container_uid = '418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787'
        time.sleep(10)  # wait for systems to start

    def tearDown(self):
        super().tearDown()
        self._stop_backend()

    def _rest_upload_firmware(self):
        testfile_path = os.path.join(get_test_data_dir(), 'container/test.zip')
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
            'requested_analysis_systems': ['software_components']
        }
        rv = self.test_client.put('/rest/firmware', data=json.dumps(data), follow_redirects=True)
        self.assertIn(b'"status": 0', rv.data, 'rest upload not successful')
        self.assertIn(self.test_container_uid.encode(), rv.data, 'uid not found in rest upload reply')

    def _rest_get_analysis_result(self):
        rv = self.test_client.get('/rest/firmware/{}'.format(self.test_container_uid), follow_redirects=True)
        self.assertIn(b'analysis_date', rv.data, 'rest analysis download not successful')
        self.assertIn(b'software_components', rv.data, 'rest analysis not successful')

    def _rest_search(self):
        rv = self.test_client.get('/rest/firmware?query={}'.format(urllib.parse.quote('{"device_class": "test_class"}')), follow_redirects=True)
        self.assertIn(self.test_container_uid.encode(), rv.data, 'test firmware not found in rest search')

    def _rest_search_fw_only(self):
        query = json.dumps({'sha256': self.test_container_uid.split('_')[0]})
        rv = self.test_client.get('/rest/firmware?query={}'.format(urllib.parse.quote(query)), follow_redirects=True)
        self.assertIn(self.test_container_uid.encode(), rv.data, 'test firmware not found in rest search')

    def _rest_update_analysis_bad_analysis(self):
        rv = self.test_client.put('/rest/firmware/{}?update={}'.format(self.test_container_uid, urllib.parse.quote('["unknown_system"]')), follow_redirects=True)
        self.assertIn('Unknown analysis system'.encode(), rv.data, "rest analysis update should break on request of non existing system")

    def _rest_update_analysis_success(self):
        rv = self.test_client.put('/rest/firmware/{}?update={}'.format(self.test_container_uid, urllib.parse.quote(json.dumps(['crypto_material']))), follow_redirects=True)
        self.assertNotIn(b'error_message', rv.data, 'Error on update request')

    def _rest_check_new_analysis_exists(self):
        rv = self.test_client.get('/rest/firmware/{}'.format(self.test_container_uid), follow_redirects=True)
        response_data = json.loads(rv.data.decode())
        assert response_data['firmware']['analysis']['crypto_material']
        assert response_data['firmware']['analysis']['crypto_material']['analysis_date'] > response_data['firmware']['analysis']['software_components']['analysis_date']

    def test_run_from_upload_to_show_analysis_and_search(self):
        self._rest_upload_firmware()
        time.sleep(15)  # wait for analysis to complete
        self._rest_get_analysis_result()
        self._rest_search()
        self._rest_search_fw_only()
        self._rest_update_analysis_bad_analysis()
        self._rest_update_analysis_success()

        time.sleep(10)  # wait for analysis to complete

        self._rest_check_new_analysis_exists()
