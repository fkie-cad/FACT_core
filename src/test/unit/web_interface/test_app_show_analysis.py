import pytest

from helperFunctions.data_conversion import make_bytes
from test.common_helper import TEST_FW, TEST_FW_2, TEST_TEXT_FILE  # pylint: disable=wrong-import-order
from test.unit.conftest import CommonIntercomMock


class IntercomMock(CommonIntercomMock):
    def add_single_file_task(self, task):
        self.task_list.append(task)


@pytest.mark.WebInterfaceUnitTestConfig(intercom_mock_class=IntercomMock)
class TestAppShowAnalysis:
    def test_app_show_analysis_get_valid_fw(self, test_client):
        result = test_client.get(f'/analysis/{TEST_FW.uid}').data
        assert b'<strong>UID:</strong> ' + make_bytes(TEST_FW.uid) in result
        assert b'data-toggle="tooltip" title="mandatory plugin description"' in result
        assert b'data-toggle="tooltip" title="optional plugin description"' in result

        # check release date not available
        assert b'1970-01-01' not in result
        assert b'unknown' in result

        result = test_client.get(f'/analysis/{TEST_FW_2.uid}').data
        assert b'unknown' not in result
        assert b'2000-01-01' in result

    def test_app_show_analysis_file_with_preview(self, test_client):
        result = test_client.get(f'/analysis/{TEST_TEXT_FILE.uid}').data
        assert b'<strong>UID:</strong> ' + make_bytes(TEST_TEXT_FILE.uid) in result
        assert b'Preview' in result
        assert b'test file:\ncontent:'

    def test_app_show_analysis_invalid_analysis(self, test_client):
        result = test_client.get(f'/analysis/{TEST_FW.uid}/this_analysis_does_not_exist/ro/{TEST_FW.uid}').data
        assert b'Error!' in result

    def test_app_single_file_analysis(self, test_client, intercom_task_list):
        result = test_client.get(f'/analysis/{TEST_FW.uid}')

        assert b'Add new analysis' in result.data
        assert b'Update analysis' in result.data

        assert not intercom_task_list
        post_new = test_client.post(
            f'/analysis/{TEST_FW.uid}',
            content_type='multipart/form-data',
            data={'analysis_systems': ['plugin_a', 'plugin_b']},
        )

        assert post_new.status_code == 302
        assert intercom_task_list
        assert intercom_task_list[0].scheduled_analysis == ['plugin_a', 'plugin_b']
