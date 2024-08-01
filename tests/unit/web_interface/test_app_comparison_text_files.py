from __future__ import annotations

import pytest

from tests.common_helper import TEST_TEXT_FILE, TEST_TEXT_FILE2, CommonDatabaseMock, create_test_firmware
from tests.unit.conftest import CommonIntercomMock, WebInterfaceUnitTestConfig


class MockInterCom(CommonIntercomMock):
    @staticmethod
    def get_file_diff(uid_pair: tuple[str, str]) -> str | None:
        if TEST_TEXT_FILE.uid in uid_pair:
            return f'file diff {TEST_TEXT_FILE.file_name}'
        raise AssertionError('if this point was reached, something went wrong')


class DbMock(CommonDatabaseMock):
    def get_object(self, uid: str, analysis_filter=None):
        if uid == TEST_TEXT_FILE.uid:
            return TEST_TEXT_FILE
        if uid == TEST_TEXT_FILE2.uid:
            return TEST_TEXT_FILE2
        if uid == 'file_1_root_uid':
            return create_test_firmware(device_name='fw1')
        if uid == 'file_2_root_uid':
            return create_test_firmware(device_name='fw2')
        raise AssertionError('if this point was reached, something went wrong')


@pytest.mark.WebInterfaceUnitTestConfig(
    WebInterfaceUnitTestConfig(
        database_mock_class=DbMock,
        intercom_mock_class=MockInterCom,
    ),
)
class TestAppComparisonTextFiles:
    def test_comparison_text_files(self, test_client):
        TEST_TEXT_FILE.processed_analysis['file_type']['result']['mime'] = 'text/plain'
        TEST_TEXT_FILE2.processed_analysis['file_type']['result']['mime'] = 'text/plain'
        response = _load_diff(test_client)
        # As the javascript rendering is done clientside we test if the diff string is valid
        assert TEST_TEXT_FILE.file_name in response.decode()

    def test_wrong_mime_type(self, test_client):
        TEST_TEXT_FILE.processed_analysis['file_type']['result']['mime'] = 'text/plain'
        TEST_TEXT_FILE2.processed_analysis['file_type']['result']['mime'] = 'some/type'
        response = _load_diff(test_client)
        assert b'compare non-text mimetypes' in response

    def test_analysis_not_finished(self, test_client):
        TEST_TEXT_FILE.processed_analysis['file_type']['result']['mime'] = None
        TEST_TEXT_FILE2.processed_analysis['file_type']['result']['mime'] = None
        response = _load_diff(test_client)
        assert b'file_type analysis is not finished' in response


def _load_diff(test_client):
    with test_client as tc:
        with tc.session_transaction() as test_session:
            test_session['uids_for_comparison'] = {
                TEST_TEXT_FILE.uid: 'file_1_root_uid',
                TEST_TEXT_FILE2.uid: 'file_2_root_uid',
            }
            test_session.modified = True
        return test_client.get('/comparison/text_files', follow_redirects=True).data
