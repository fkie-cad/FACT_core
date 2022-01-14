from test.common_helper import TEST_FW, TEST_TEXT_FILE, CommonIntercomMock
from test.unit.web_interface.base import WebInterfaceTest


class BinarySearchMock(CommonIntercomMock):

    @staticmethod
    def get_binary_and_filename(uid):
        if uid == TEST_FW.uid:
            return TEST_FW.binary, TEST_FW.file_name
        if uid == TEST_TEXT_FILE.uid:
            return TEST_TEXT_FILE.binary, TEST_TEXT_FILE.file_name
        return None

    @staticmethod
    def get_repacked_binary_and_file_name(uid):
        if uid == TEST_FW.uid:
            return TEST_FW.binary, f'{TEST_FW.file_name}.tar.gz'
        return None, None


class TestAppDownload(WebInterfaceTest):

    def setup(self, *_, **__):
        super().setup(intercom_mock=BinarySearchMock)

    def test_app_download_raw_invalid(self):
        rv = self.test_client.get('/download/invalid_uid')
        assert b'File not found in database: invalid_uid' in rv.data

    def test_app_download_raw_error(self):
        rv = self.test_client.get('/download/error')
        assert b'<strong>Error!</strong>  timeout' in rv.data

    def test_app_download_raw(self):
        rv = self.test_client.get('/download/{}'.format(TEST_FW.uid))
        assert TEST_FW.binary in rv.data
        assert 'attachment; filename=test.zip' in rv.headers['Content-Disposition']

    def test_app_tar_download(self):
        rv = self.test_client.get('/tar-download/{}'.format(TEST_FW.uid))
        assert TEST_FW.binary in rv.data
        assert 'attachment; filename=test.zip' in rv.headers['Content-Disposition']
