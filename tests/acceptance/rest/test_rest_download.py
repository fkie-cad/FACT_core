import urllib.parse
from base64 import standard_b64encode

import pytest

from fact.test.common_helper import create_test_firmware

test_fw = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')


class TestRestDownloadFirmware:
    def _rest_search(self, test_client):
        query = '{"device_class": "test class"}'
        rv = test_client.get(f'/rest/firmware?query={urllib.parse.quote(query)}', follow_redirects=True)
        assert test_fw.uid.encode() in rv.data, 'test firmware not found in rest search'

    def _rest_download(self, test_client):
        rv = test_client.get(f'/rest/binary/{test_fw.uid}', follow_redirects=True)
        assert standard_b64encode(test_fw.binary) in rv.data, 'rest download response incorrect'
        assert f'"file_name": "{test_fw.file_name}"'.encode() in rv.data, 'rest download response incorrect'
        assert f'"SHA256": "{test_fw.sha256}"'.encode() in rv.data, 'rest download response incorrect'

    @pytest.mark.usefixtures('intercom_backend_binding')
    def test_run_from_upload_to_show_analysis(self, test_client, backend_db, fsorganizer):
        backend_db.add_object(test_fw)
        fsorganizer.store_file(test_fw)

        self._rest_search(test_client)
        self._rest_download(test_client)
