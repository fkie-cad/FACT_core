from base64 import standard_b64decode

from test.common_helper import TEST_FW

from ..base import WebInterfaceTest


class TestRestBinary(WebInterfaceTest):
    def test_bad_requests(self):
        result = self.test_client.get('/rest/binary').data
        assert b'404 Not Found' in result

    def test_non_existing_uid(self):
        result = self.test_client.get('/rest/binary/some_uid').json
        assert 'No firmware with UID some_uid' in result['error_message']

    def test_successful_download(self):
        result = self.test_client.get(f'/rest/binary/{TEST_FW.uid}').json
        assert result['SHA256'] == TEST_FW.uid.split('_')[0]
        assert result['file_name'] == 'test.zip'
        assert isinstance(standard_b64decode(result['binary']), bytes)

    def test_successful_tar_download(self):
        result = self.test_client.get(f'/rest/binary/{TEST_FW.uid}?tar=true').json
        assert result['file_name'] == 'test.zip.tar.gz'
        assert isinstance(standard_b64decode(result['binary']), bytes)

    def test_bad_tar_flag(self):
        result = self.test_client.get(f'/rest/binary/{TEST_FW.uid}?tar=True').json
        assert result['status'] == 1
        assert 'tar must be true or false' in result['error_message']
