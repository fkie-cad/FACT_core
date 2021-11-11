import time
import urllib.parse
from base64 import standard_b64encode

from storage.db_interface_backend import BackEndDbInterface
from test.acceptance.base import TestAcceptanceBase
from test.common_helper import create_test_firmware


class TestIntegrationRestDownloadFirmware(TestAcceptanceBase):

    def setUp(self):
        super().setUp()
        self._start_backend()
        self.db_backend = BackEndDbInterface(config=self.config)
        time.sleep(2)  # wait for systems to start

    def tearDown(self):
        self.db_backend.shutdown()
        self._stop_backend()
        super().tearDown()

    def _rest_search(self):
        query = '{"device_class": "test class"}'
        rv = self.test_client.get(f'/rest/firmware?query={urllib.parse.quote(query)}', follow_redirects=True)
        assert self.test_fw.uid.encode() in rv.data, 'test firmware not found in rest search'

    def _rest_download(self):
        rv = self.test_client.get(f'/rest/binary/{self.test_fw.uid}', follow_redirects=True)
        assert standard_b64encode(self.test_fw.binary) in rv.data, 'rest download response incorrect'
        assert f'"file_name": "{self.test_fw.file_name}"'.encode() in rv.data, 'rest download response incorrect'
        assert f'"SHA256": "{self.test_fw.sha256}"'.encode() in rv.data, 'rest download response incorrect'

    def test_run_from_upload_to_show_analysis(self):
        self.test_fw = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
        self.db_backend.add_firmware(self.test_fw)

        self._rest_search()
        self._rest_download()
