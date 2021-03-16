from io import BytesIO
from pathlib import Path

from test.unit.web_interface.base import WebInterfaceTest


class TestAppUpload(WebInterfaceTest):

    def _put_file_in_upload_dir(self, file_name):
        upload_dir = self.config.get('data_storage', 'upload_storage_dir')
        (Path(upload_dir) / file_name).write_bytes(b'test_file_content')

    @staticmethod
    def _get_test_data(version='1.0'):
        return {
            'file_name': 'test_file.txt',
            'device_name': 'test_device',
            'device_part': 'kernel',
            'device_class': 'test_class',
            'version': version,
            'vendor': 'test_vendor',
            'release_date': '01.01.1970',
            'tags': '',
            'analysis_systems': ['dummy']
        }

    def test_app_upload_get(self):
        rv = self.test_client.get('/upload')
        assert b'<h3 class="mb-3">Upload Firmware</h3>' in rv.data
        assert b'value="default_plugin" checked' in rv.data
        assert b'value="mandatory_plugin"' not in rv.data
        assert b'value="optional_plugin" unchecked' in rv.data

    def test_app_upload_missing_file(self):
        rv = self.test_client.post('/upload', content_type='multipart/form-data', follow_redirects=True, data=self._get_test_data())
        assert b'Uploaded file not found' in rv.data
        assert len(self.mocked_interface.tasks) == 0, 'task added to intercom but should not'

    def test_app_upload_invalid_firmware(self):
        self._put_file_in_upload_dir('test_file.txt')
        rv = self.test_client.post('/upload', content_type='multipart/form-data', follow_redirects=True, data=self._get_test_data(version=''))
        assert b'Please specify the version' in rv.data
        assert len(self.mocked_interface.tasks) == 0, 'task added to intercom but should not'

    def test_app_upload_valid_firmware(self):
        self._put_file_in_upload_dir('test_file.txt')
        rv = self.test_client.post('/upload', content_type='multipart/form-data', data=self._get_test_data(), follow_redirects=True)
        assert b'Upload Successful' in rv.data
        assert b'c1f95369a99b765e93c335067e77a7d91af3076d2d3d64aacd04e1e0a810b3ed_17' in rv.data
        assert self.mocked_interface.tasks[0].uid == 'c1f95369a99b765e93c335067e77a7d91af3076d2d3d64aacd04e1e0a810b3ed_17', 'fw not added to intercom'
        assert 'dummy' in self.mocked_interface.tasks[0].scheduled_analysis, 'analysis system not added'
        assert self.mocked_interface.tasks[0].file_name == 'test_file.txt', 'file name not correct'

    def test_upload_file(self):
        data = self._get_file_upload_data()
        response = self.test_client.post('/upload-file', content_type='multipart/form-data', data=data, follow_redirects=True)
        assert response.status_code == 200
        assert response.data == b'Chunk upload successful'

    def test_upload_file_size_mismatch(self):
        data = self._get_file_upload_data(dzchunkindex=9)
        response = self.test_client.post('/upload-file', content_type='multipart/form-data', data=data, follow_redirects=True)
        assert response.status_code == 500
        assert response.data == b'Size mismatch'

    def test_upload_file_exists(self):
        self._put_file_in_upload_dir('test_file.txt')
        data = self._get_file_upload_data()
        response = self.test_client.post('/upload-file', content_type='multipart/form-data', data=data, follow_redirects=True)
        assert response.status_code == 400
        assert response.data == b'File already exists'

    @staticmethod
    def _get_file_upload_data(dzchunkindex=0):
        return {
            'file': (BytesIO(b'test_file_content'), 'test_file.txt'),
            'dzchunkindex': dzchunkindex,
            'dzchunkbyteoffset': 0,
            'dztotalchunkcount': 10,
            'dztotalfilesize': 1000,
        }
