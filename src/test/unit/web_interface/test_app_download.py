from test.common_helper import TEST_FW
from test.unit.web_interface.base import WebInterfaceTest


class TestAppDownload(WebInterfaceTest):
    def test_app_download_raw_invalid(self):
        rv = self.test_client.get('/download/invalid_uid')
        assert b'File not found in database: invalid_uid' in rv.data

    def test_app_download_raw_error(self):
        rv = self.test_client.get('/download/error')
        assert b'<strong>Error!</strong>  timeout' in rv.data

    def test_app_download_raw(self):
        rv = self.test_client.get(f'/download/{TEST_FW.uid}')
        assert TEST_FW.binary in rv.data
        assert 'attachment; filename=test.zip' in rv.headers['Content-Disposition']

    def test_app_tar_download(self):
        rv = self.test_client.get(f'/tar-download/{TEST_FW.uid}')
        assert TEST_FW.binary in rv.data
        assert 'attachment; filename=test.zip' in rv.headers['Content-Disposition']
