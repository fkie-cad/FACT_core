import unittest

from test.common_helper import TEST_TEXT_FILE
from test.unit.web_interface.base import WebInterfaceTest


class MockBinaryService:
    def __init__(self, config=None):
        pass

    def get_binary_and_file_name(self, uid: str):
        assert uid == TEST_TEXT_FILE.uid
        return b'file content', TEST_TEXT_FILE.file_name


class TestAppComparisonTextFiles(WebInterfaceTest):

    def test_comparison_text_files(self):
        new_patch = unittest.mock.patch(target='storage.binary_service.BinaryService.__new__', new=lambda *_, **__: MockBinaryService())
        new_patch.start()
        with self.test_client as tc:
            with tc.session_transaction() as test_session:
                test_session['uids_for_comparison'] = [TEST_TEXT_FILE.uid, TEST_TEXT_FILE.uid]

            rv = self.test_client.get('/comparison/text_files')
            print(rv.data)

            assert TEST_TEXT_FILE.file_name in rv.data.decode()

        new_patch.stop()
