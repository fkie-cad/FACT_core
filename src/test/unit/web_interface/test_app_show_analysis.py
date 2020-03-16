from helperFunctions.dataConversion import make_bytes
from test.common_helper import TEST_FW, TEST_FW_2, TEST_TEXT_FILE
from test.unit.web_interface.base import WebInterfaceTest


class TestAppShowAnalysis(WebInterfaceTest):

    def test_app_show_analysis_get_valid_fw(self):
        result = self.test_client.get('/analysis/{}'.format(TEST_FW.uid)).data
        assert b'<strong>UID:</strong> ' + make_bytes(TEST_FW.uid) in result
        assert b'data-toggle="tooltip" title="mandatory plugin description"' in result
        assert b'data-toggle="tooltip" title="optional plugin description"' in result

        # check release date not available
        assert b'1970-01-01' not in result
        assert b'unknown' in result

        # check file preview
        assert b'Preview' not in result

        result = self.test_client.get('/analysis/{}'.format(TEST_FW_2.uid)).data
        assert b'unknown' not in result
        assert b'2000-01-01' in result

    def test_app_show_analysis_file_with_preview(self):
        result = self.test_client.get('/analysis/{}'.format(TEST_TEXT_FILE.uid)).data
        assert b'<strong>UID:</strong> ' + make_bytes(TEST_TEXT_FILE.uid) in result
        assert b'Preview' in result
        assert b'test file:\ncontent:'

    def test_app_single_file_analysis(self):
        result = self.test_client.get('/analysis/{}'.format(TEST_FW.uid))

        assert b'Add new analysis' in result.data
        assert b'Update analysis' in result.data

        assert not self.mocked_interface.tasks
        post_new = self.test_client.post('/analysis/{}'.format(TEST_FW.uid), content_type='multipart/form-data', data={'analysis_systems': ['plugin_a', 'plugin_b']})

        assert post_new.status_code == 200
        assert self.mocked_interface.tasks
        assert self.mocked_interface.tasks[0].scheduled_analysis == ['plugin_a', 'plugin_b']
