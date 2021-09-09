# pylint: disable=wrong-import-order

import json
import time
import urllib.parse
from multiprocessing import Event, Value

from storage.db_interface_backend import BackEndDbInterface
from test.acceptance.base import TestAcceptanceBase
from test.common_helper import get_firmware_for_rest_upload_test


class TestRestFirmware(TestAcceptanceBase):

    def setUp(self):
        super().setUp()
        self.analysis_finished_event = Event()
        self.elements_finished_analyzing = Value('i', 0)
        self.db_backend_service = BackEndDbInterface(config=self.config)
        self._start_backend(post_analysis=self._analysis_callback)
        self.test_container_uid = '418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787'
        time.sleep(2)  # wait for systems to start

    def tearDown(self):
        self._stop_backend()
        self.db_backend_service.shutdown()
        super().tearDown()

    def _analysis_callback(self, fo):
        self.db_backend_service.add_analysis(fo)
        self.elements_finished_analyzing.value += 1
        if self.elements_finished_analyzing.value == 4 * 3:  # container including 3 files times 3 plugins
            self.analysis_finished_event.set()

    def _rest_upload_firmware(self):
        data = get_firmware_for_rest_upload_test()
        rv = self.test_client.put('/rest/firmware', json=data, follow_redirects=True)
        assert b'"status": 0' in rv.data, 'rest upload not successful'
        assert self.test_container_uid.encode() in rv.data, 'uid not found in rest upload reply'

    def _rest_get_analysis_result(self):
        rv = self.test_client.get(f'/rest/firmware/{self.test_container_uid}', follow_redirects=True)
        assert b'analysis_date' in rv.data, 'rest analysis download not successful'
        assert b'software_components' in rv.data, 'rest analysis not successful'
        assert b'"device_part": "test_part' in rv.data, 'device part not present'

    def _rest_search(self):
        query = urllib.parse.quote('{"device_class": "test_class"}')
        rv = self.test_client.get(f'/rest/firmware?query={query}', follow_redirects=True)
        assert self.test_container_uid.encode() in rv.data, 'test firmware not found in rest search'

    def _rest_search_fw_only(self):
        query = json.dumps({'sha256': self.test_container_uid.split('_')[0]})
        rv = self.test_client.get(f'/rest/firmware?query={urllib.parse.quote(query)}', follow_redirects=True)
        assert self.test_container_uid.encode() in rv.data, 'test firmware not found in rest search'

    def _rest_update_analysis_bad_analysis(self):
        query = urllib.parse.quote('["unknown_system"]')
        rv = self.test_client.put(f'/rest/firmware/{self.test_container_uid}?update={query}', follow_redirects=True)
        assert 'Unknown analysis system'.encode() in rv.data, "rest analysis update should break on request of non existing system"

    def _rest_update_analysis_success(self):
        update = urllib.parse.quote(json.dumps(['crypto_material']))
        rv = self.test_client.put(f'/rest/firmware/{self.test_container_uid}?update={update}', follow_redirects=True)
        assert b'error_message' not in rv.data, 'Error on update request'

    def _rest_check_new_analysis_exists(self):
        rv = self.test_client.get(f'/rest/firmware/{self.test_container_uid}', follow_redirects=True)
        response_data = json.loads(rv.data.decode())
        assert response_data['firmware']['analysis']['crypto_material']
        assert response_data['firmware']['analysis']['crypto_material']['analysis_date'] > response_data['firmware']['analysis']['software_components']['analysis_date']

    def test_run_from_upload_to_show_analysis_and_search(self):
        self._rest_upload_firmware()
        self.analysis_finished_event.wait(timeout=15)
        self.elements_finished_analyzing.value = 4 * 2  # only one plugin to update so we offset with 4 times 2 plugins
        self.analysis_finished_event.clear()
        self._rest_get_analysis_result()
        self._rest_search()
        self._rest_search_fw_only()
        self._rest_update_analysis_bad_analysis()
        self._rest_update_analysis_success()

        self.analysis_finished_event.wait(timeout=10)

        self._rest_check_new_analysis_exists()
