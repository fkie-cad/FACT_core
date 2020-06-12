from base64 import standard_b64encode
import time
import urllib.parse

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
        rv = self.test_client.get('/rest/firmware?query={}'.format(urllib.parse.quote('{"device_class": "test class"}')), follow_redirects=True)
        self.assertIn(self.test_fw.uid.encode(), rv.data, "test firmware not found in rest search")

    def _rest_download(self):
        rv = self.test_client.get('/rest/binary/{}'.format(self.test_fw.uid), follow_redirects=True)
        self.assertIn(standard_b64encode(self.test_fw.binary), rv.data, "rest download response incorrect")
        self.assertIn('"file_name": "{}"'.format(self.test_fw.file_name).encode(), rv.data, "rest download response incorrect")
        self.assertIn('"SHA256": "{}"'.format(self.test_fw.sha256).encode(), rv.data, "rest download response incorrect")

    def test_run_from_upload_to_show_analysis(self):
        self.test_fw = create_test_firmware(device_class="test class", device_name="test device", vendor="test vendor")
        self.db_backend.add_firmware(self.test_fw)

        self._rest_search()
        self._rest_download()
