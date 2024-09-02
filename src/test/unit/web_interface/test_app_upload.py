from io import BytesIO


class TestAppUpload:
    def test_app_upload_get(self, test_client):
        rv = test_client.get('/upload')
        assert b'<h3 class="mb-3">Upload Firmware</h3>' in rv.data
        assert b'value="default_plugin" checked' in rv.data
        assert b'value="mandatory_plugin"' not in rv.data
        assert b'value="optional_plugin" >' in rv.data

    def test_app_upload_invalid_firmware(self, test_client, intercom_task_list):
        rv = test_client.post(
            '/upload',
            content_type='multipart/form-data',
            data={
                'file': (BytesIO(b'test_file_content'), 'test_file.txt'),
                'device_name': 'test_device',
                'device_part': 'kernel',
                'version': '',
                'vendor': 'test_vendor',
                'release_date': '01.01.1970',
                'tags': '',
                'analysis_systems': ['dummy'],
            },
            follow_redirects=True,
        )
        assert b'Bad Request' in rv.data
        assert len(intercom_task_list) == 0, 'task added to intercom but should not'

    def test_app_upload_valid_firmware(self, test_client, intercom_task_list):
        rv = test_client.post(
            '/upload',
            content_type='multipart/form-data',
            data={
                'file': (BytesIO(b'test_file_content'), 'test_file.txt'),
                'device_name': 'test_device',
                'device_part': 'complete',
                'device_class': 'test_class',
                'version': '1.0',
                'vendor': 'test_vendor',
                'release_date': '01.01.1970',
                'tags': 'tag1,tag2',
                'analysis_systems': ['dummy'],
            },
            follow_redirects=True,
        )
        assert b'Upload Successful' in rv.data
        assert b'c1f95369a99b765e93c335067e77a7d91af3076d2d3d64aacd04e1e0a810b3ed_17' in rv.data
        assert (
            intercom_task_list[0].uid == 'c1f95369a99b765e93c335067e77a7d91af3076d2d3d64aacd04e1e0a810b3ed_17'
        ), 'fw not added to intercom'
        assert 'dummy' in intercom_task_list[0].scheduled_analysis, 'analysis system not added'
        assert intercom_task_list[0].file_name == 'test_file.txt', 'file name not correct'
