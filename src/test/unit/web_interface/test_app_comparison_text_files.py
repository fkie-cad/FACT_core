from test.common_helper import TEST_TEXT_FILE, TEST_TEXT_FILE2, create_test_firmware
from test.unit.web_interface.base import WebInterfaceTest


class MockInterCom:
    def get_binary_and_filename(self, uid: str):
        if uid == TEST_TEXT_FILE.uid:
            return b'file content\nfirst', TEST_TEXT_FILE.file_name
        elif uid == TEST_TEXT_FILE2.uid:
            return b'file content\nsecond', TEST_TEXT_FILE2.file_name
        else:
            assert False

    def get_object(self, uid: str):
        if uid == TEST_TEXT_FILE.uid:
            return TEST_TEXT_FILE
        elif uid == TEST_TEXT_FILE2.uid:
            return TEST_TEXT_FILE2
        elif uid == 'file_1_root_uid':
            return create_test_firmware(device_name='fw1')
        elif uid == 'file_2_root_uid':
            return create_test_firmware(device_name='fw2')
        else:
            assert False

    def shutdown(self):
        pass


class TestAppComparisonTextFiles(WebInterfaceTest):
    def setUp(self, db_mock=MockInterCom):
        super().setUp(db_mock=db_mock)

    def test_comparison_text_files(self):
        TEST_TEXT_FILE.processed_analysis['file_type']['mime'] = 'text/plain'
        TEST_TEXT_FILE2.processed_analysis['file_type']['mime'] = 'text/plain'
        response = self._load_diff()
        # As the javascript rendering is done clientside we test if the diffstring is valid
        assert TEST_TEXT_FILE.file_name in response.decode()

    def test_wrong_mime_type(self):
        TEST_TEXT_FILE.processed_analysis['file_type']['mime'] = 'text/plain'
        TEST_TEXT_FILE2.processed_analysis['file_type']['mime'] = 'some/type'
        response = self._load_diff()
        assert b'compare non-text mimetypes' in response

    def test_analysis_not_finished(self):
        TEST_TEXT_FILE.processed_analysis['file_type']['mime'] = None
        TEST_TEXT_FILE2.processed_analysis['file_type']['mime'] = None
        response = self._load_diff()
        assert b'file_type analysis is not finished' in response

    def _load_diff(self):
        with self.test_client as tc:
            with tc.session_transaction() as test_session:
                test_session['uids_for_comparison'] = {
                    TEST_TEXT_FILE.uid: 'file_1_root_uid',
                    TEST_TEXT_FILE2.uid: 'file_2_root_uid'
                }
                test_session.modified = True
            return self.test_client.get('/comparison/text_files').data
