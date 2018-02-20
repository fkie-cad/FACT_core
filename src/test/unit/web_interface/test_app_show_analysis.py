from helperFunctions.dataConversion import make_bytes
from test.common_helper import TEST_FW, TEST_FW_2, TEST_TEXT_FILE
from test.unit.web_interface.base import WebInterfaceTest


class TestAppShowAnalysis(WebInterfaceTest):

    def test_app_show_analysis_get_valid_fw(self):
        result = self.test_client.get('/analysis/{}'.format(TEST_FW.get_uid())).data
        assert b'<strong>UID:</strong> ' + make_bytes(TEST_FW.get_uid()) in result
        assert b'data-toggle="tooltip" title="mandatory plugin description"' in result
        assert b'data-toggle="tooltip" title="optional plugin description"' in result
        assert b'data-toggle="tooltip" title="default plugin description"' not in result
        # check release date not available
        assert b'1970-01-01' not in result
        assert b'unknown' in result
        # check file preview
        assert b'Preview' not in result

        result = self.test_client.get('/analysis/{}'.format(TEST_FW_2.get_uid())).data
        assert b'unknown' not in result
        assert b'2000-01-01' in result

    def test_app_show_analysis_file_with_preview(self):
        result = self.test_client.get('/analysis/{}'.format(TEST_TEXT_FILE.get_uid())).data
        assert b'<strong>UID:</strong> ' + make_bytes(TEST_TEXT_FILE.get_uid()) in result
        assert b'Preview' in result
        assert b'test file:\ncontent:'
