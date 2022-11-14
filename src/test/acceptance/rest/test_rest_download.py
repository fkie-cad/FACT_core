import urllib.parse
from base64 import standard_b64encode

from test.acceptance.base import TestAcceptanceBaseWithDb
from test.common_helper import create_test_firmware


class TestRestDownloadFirmware(TestAcceptanceBaseWithDb):
    def setUp(self):
        super().setUp()
        self.test_fw = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')

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
        self.db_backend.add_object(self.test_fw)
        self.fs_organizer.store_file(self.test_fw)

        self._rest_search()
        self._rest_download()
