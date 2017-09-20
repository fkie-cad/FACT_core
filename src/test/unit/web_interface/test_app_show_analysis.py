from helperFunctions.dataConversion import make_bytes
from test.common_helper import TEST_FW, TEST_TEXT_FILE
from test.unit.web_interface.base import WebInterfaceTest


class TestAppShowAnalysis(WebInterfaceTest):

    def test_app_show_analysis_get_valid_fw(self):
        rv = self.test_client.get('/analysis/{}'.format(TEST_FW.get_uid()))
        assert b'<strong>UID:</strong> ' + make_bytes(TEST_FW.get_uid()) in rv.data
        assert b'data-toggle="tooltip" title="mandatory plugin description"' in rv.data
        assert b'data-toggle="tooltip" title="optional plugin description"' in rv.data
        assert b'data-toggle="tooltip" title="default plugin description"' not in rv.data
        # check release date not available
        assert b'1970-01-01' not in rv.data
        assert b'unknown' in rv.data
        # check file preview
        assert b'Preview' not in rv.data

    def test_app_show_analysis_file_with_preview(self):
        rv = self.test_client.get('/analysis/{}'.format(TEST_TEXT_FILE.get_uid()))
        assert b'<strong>UID:</strong> ' + make_bytes(TEST_TEXT_FILE.get_uid()) in rv.data
        assert b'Preview' in rv.data
        assert b'test file:\ncontent:'
