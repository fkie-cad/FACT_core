from test.common_helper import TEST_TEXT_FILE, TEST_TEXT_FILE2
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
        else:
            assert False

    def shutdown(self):
        pass


class TestAppComparisonTextFiles(WebInterfaceTest):
    def setUp(self):
        super().setUp(db_mock=MockInterCom)

    def test_comparison_text_files(self):
        TEST_TEXT_FILE.processed_analysis['file_type']['mime'] = 'text/plain'
        TEST_TEXT_FILE2.processed_analysis['file_type']['mime'] = 'text/plain'
        with self.test_client as tc:
            with tc.session_transaction() as test_session:
                test_session['uids_for_comparison'] = [TEST_TEXT_FILE.uid, TEST_TEXT_FILE2.uid]

            rv = self.test_client.get('/comparison/text_files')

            # As the javascript rendering is done clientside we test if the diffstring is valid
            assert TEST_TEXT_FILE.file_name in rv.data.decode()
